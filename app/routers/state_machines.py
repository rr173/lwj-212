import json
from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from app.models import (
    StateMachineCreate,
    StateMachineUpdate,
    StateMachineOut,
    StateMachineDetailOut,
    StateOut,
    TransitionOut,
    ValidationResult,
    ViolationFrame,
    StateTransitionHistoryEntry,
    InferenceResult,
    CandidateState,
    CandidateTransition,
    ParseResult,
    FrameOut,
    FieldDef,
)
from app.database import get_db
from app.utils import validate_hex, hex_to_bytes
from app.parser import parse_message

router = APIRouter(prefix="/api/state-machines", tags=["state-machines"])

MAX_STATES = 20
MAX_TRANSITIONS = 50


async def _get_template_fields(template_id: int, version: Optional[int] = None):
    db = await get_db()
    try:
        if version is not None:
            t_rows = await db.execute_fetchall(
                "SELECT * FROM template_versions WHERE template_id = ? AND version = ?",
                (template_id, version),
            )
            if not t_rows:
                raise HTTPException(status_code=404, detail="template version not found")
            actual_version = version
        else:
            t_rows = await db.execute_fetchall(
                "SELECT * FROM templates WHERE id = ?", (template_id,)
            )
            if not t_rows:
                raise HTTPException(status_code=404, detail="template not found")
            v_rows = await db.execute_fetchall(
                "SELECT MAX(version) as max_version FROM template_versions WHERE template_id = ?",
                (template_id,),
            )
            actual_version = v_rows[0]["max_version"] or 1
            t_rows = await db.execute_fetchall(
                "SELECT * FROM template_versions WHERE template_id = ? AND version = ?",
                (template_id, actual_version),
            )
    finally:
        await db.close()

    fields = [FieldDef(**f) for f in json.loads(t_rows[0]["fields_json"])]
    return fields, actual_version


def _parse_result_from_json(json_str: Optional[str]) -> Optional[ParseResult]:
    if not json_str:
        return None
    try:
        data = json.loads(json_str)
        return ParseResult(**data)
    except Exception:
        return None


def _row_to_state_out(row) -> StateOut:
    return StateOut(
        id=row["id"],
        state_machine_id=row["state_machine_id"],
        name=row["name"],
        state_type=row["state_type"],
    )


def _row_to_transition_out(row) -> TransitionOut:
    return TransitionOut(
        id=row["id"],
        state_machine_id=row["state_machine_id"],
        from_state_id=row["from_state_id"],
        to_state_id=row["to_state_id"],
        from_state_name=row["from_state_name"],
        to_state_name=row["to_state_name"],
        trigger_field=row["trigger_field"],
        trigger_value=row["trigger_value"],
        direction_constraint=row["direction_constraint"],
    )


async def _get_state_machine_or_404(state_machine_id: int):
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM state_machines WHERE id = ?", (state_machine_id,)
        )
    finally:
        await db.close()
    if not rows:
        raise HTTPException(status_code=404, detail="state machine not found")
    return rows[0]


def _validate_state_machine_constraints(states: list, transitions: list):
    if len(states) > MAX_STATES:
        raise HTTPException(
            status_code=400,
            detail=f"state machine exceeds maximum state count of {MAX_STATES}",
        )
    if len(transitions) > MAX_TRANSITIONS:
        raise HTTPException(
            status_code=400,
            detail=f"state machine exceeds maximum transition count of {MAX_TRANSITIONS}",
        )

    initial_states = [s for s in states if s.state_type == "initial"]
    if len(initial_states) != 1:
        raise HTTPException(
            status_code=400,
            detail="state machine must have exactly one initial state",
        )

    state_names = [s.name for s in states]
    if len(state_names) != len(set(state_names)):
        raise HTTPException(
            status_code=400,
            detail="state names must be unique within a state machine",
        )


@router.post("", response_model=StateMachineDetailOut, status_code=201)
async def create_state_machine(body: StateMachineCreate):
    _validate_state_machine_constraints(body.states, body.transitions)

    db = await get_db()
    try:
        t_rows = await db.execute_fetchall(
            "SELECT id FROM templates WHERE id = ?", (body.template_id,)
        )
        if not t_rows:
            raise HTTPException(status_code=404, detail="template not found")

        existing = await db.execute_fetchall(
            "SELECT id FROM state_machines WHERE template_id = ?", (body.template_id,)
        )
        if existing:
            raise HTTPException(
                status_code=400,
                detail="a template can only be bound to one state machine",
            )

        cursor = await db.execute(
            "INSERT INTO state_machines (template_id, name, description) VALUES (?, ?, ?)",
            (body.template_id, body.name, body.description),
        )
        state_machine_id = cursor.lastrowid

        state_id_map: dict[str, int] = {}
        for state in body.states:
            cur = await db.execute(
                "INSERT INTO sm_states (state_machine_id, name, state_type) VALUES (?, ?, ?)",
                (state_machine_id, state.name, state.state_type),
            )
            state_id_map[state.name] = cur.lastrowid

        terminal_state_names = {
            s.name for s in body.states if s.state_type == "terminal"
        }

        for trans in body.transitions:
            if trans.from_state_name not in state_id_map:
                raise HTTPException(
                    status_code=400,
                    detail=f"transition references non-existent state: {trans.from_state_name}",
                )
            if trans.to_state_name not in state_id_map:
                raise HTTPException(
                    status_code=400,
                    detail=f"transition references non-existent state: {trans.to_state_name}",
                )

            if trans.from_state_name in terminal_state_names:
                raise HTTPException(
                    status_code=400,
                    detail=f"transitions from terminal state '{trans.from_state_name}' are not allowed",
                )

            from_id = state_id_map[trans.from_state_name]
            to_id = state_id_map[trans.to_state_name]

            await db.execute(
                """
                INSERT INTO sm_transitions 
                (state_machine_id, from_state_id, to_state_id, trigger_field, trigger_value, direction_constraint)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    state_machine_id,
                    from_id,
                    to_id,
                    trans.trigger_field,
                    trans.trigger_value,
                    trans.direction_constraint,
                ),
            )

        await db.commit()

        sm_row = (await db.execute_fetchall(
            "SELECT * FROM state_machines WHERE id = ?", (state_machine_id,)
        ))[0]

        state_rows = await db.execute_fetchall(
            "SELECT * FROM sm_states WHERE state_machine_id = ? ORDER BY id",
            (state_machine_id,),
        )

        trans_rows = await db.execute_fetchall(
            """
            SELECT t.*, 
                   s_from.name as from_state_name,
                   s_to.name as to_state_name
            FROM sm_transitions t
            JOIN sm_states s_from ON t.from_state_id = s_from.id
            JOIN sm_states s_to ON t.to_state_id = s_to.id
            WHERE t.state_machine_id = ?
            ORDER BY t.id
            """,
            (state_machine_id,),
        )
    finally:
        await db.close()

    return StateMachineDetailOut(
        id=sm_row["id"],
        template_id=sm_row["template_id"],
        name=sm_row["name"],
        description=sm_row["description"] or "",
        states=[_row_to_state_out(r) for r in state_rows],
        transitions=[_row_to_transition_out(r) for r in trans_rows],
        created_at=sm_row["created_at"] or "",
    )


@router.get("", response_model=list[StateMachineOut])
async def list_state_machines(
    template_id: Optional[int] = Query(default=None, description="Filter by template ID"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    db = await get_db()
    try:
        query = "SELECT * FROM state_machines"
        params = []
        if template_id is not None:
            query += " WHERE template_id = ?"
            params.append(template_id)
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        sm_rows = await db.execute_fetchall(query, params)

        sm_ids = [r["id"] for r in sm_rows]
        state_counts: dict[int, int] = {}
        trans_counts: dict[int, int] = {}

        if sm_ids:
            placeholders = ",".join("?" * len(sm_ids))
            sc_rows = await db.execute_fetchall(
                f"SELECT state_machine_id, COUNT(*) as cnt FROM sm_states WHERE state_machine_id IN ({placeholders}) GROUP BY state_machine_id",
                sm_ids,
            )
            for r in sc_rows:
                state_counts[r["state_machine_id"]] = r["cnt"]

            tc_rows = await db.execute_fetchall(
                f"SELECT state_machine_id, COUNT(*) as cnt FROM sm_transitions WHERE state_machine_id IN ({placeholders}) GROUP BY state_machine_id",
                sm_ids,
            )
            for r in tc_rows:
                trans_counts[r["state_machine_id"]] = r["cnt"]
    finally:
        await db.close()

    return [
        StateMachineOut(
            id=r["id"],
            template_id=r["template_id"],
            name=r["name"],
            description=r["description"] or "",
            state_count=state_counts.get(r["id"], 0),
            transition_count=trans_counts.get(r["id"], 0),
            created_at=r["created_at"] or "",
        )
        for r in sm_rows
    ]


@router.get("/{state_machine_id}", response_model=StateMachineDetailOut)
async def get_state_machine(state_machine_id: int):
    await _get_state_machine_or_404(state_machine_id)

    db = await get_db()
    try:
        sm_row = (await db.execute_fetchall(
            "SELECT * FROM state_machines WHERE id = ?", (state_machine_id,)
        ))[0]

        state_rows = await db.execute_fetchall(
            "SELECT * FROM sm_states WHERE state_machine_id = ? ORDER BY id",
            (state_machine_id,),
        )

        trans_rows = await db.execute_fetchall(
            """
            SELECT t.*, 
                   s_from.name as from_state_name,
                   s_to.name as to_state_name
            FROM sm_transitions t
            JOIN sm_states s_from ON t.from_state_id = s_from.id
            JOIN sm_states s_to ON t.to_state_id = s_to.id
            WHERE t.state_machine_id = ?
            ORDER BY t.id
            """,
            (state_machine_id,),
        )
    finally:
        await db.close()

    return StateMachineDetailOut(
        id=sm_row["id"],
        template_id=sm_row["template_id"],
        name=sm_row["name"],
        description=sm_row["description"] or "",
        states=[_row_to_state_out(r) for r in state_rows],
        transitions=[_row_to_transition_out(r) for r in trans_rows],
        created_at=sm_row["created_at"] or "",
    )


@router.put("/{state_machine_id}", response_model=StateMachineDetailOut)
async def update_state_machine(state_machine_id: int, body: StateMachineUpdate):
    await _get_state_machine_or_404(state_machine_id)

    db = await get_db()
    try:
        if body.name is not None or body.description is not None:
            updates = []
            params = []
            if body.name is not None:
                updates.append("name = ?")
                params.append(body.name)
            if body.description is not None:
                updates.append("description = ?")
                params.append(body.description)
            params.append(state_machine_id)

            await db.execute(
                f"UPDATE state_machines SET {', '.join(updates)} WHERE id = ?",
                params,
            )

        if body.states is not None and body.transitions is not None:
            _validate_state_machine_constraints(body.states, body.transitions)

            await db.execute(
                "DELETE FROM sm_transitions WHERE state_machine_id = ?",
                (state_machine_id,),
            )
            await db.execute(
                "DELETE FROM sm_states WHERE state_machine_id = ?",
                (state_machine_id,),
            )

            state_id_map: dict[str, int] = {}
            for state in body.states:
                cur = await db.execute(
                    "INSERT INTO sm_states (state_machine_id, name, state_type) VALUES (?, ?, ?)",
                    (state_machine_id, state.name, state.state_type),
                )
                state_id_map[state.name] = cur.lastrowid

            terminal_state_names = {
                s.name for s in body.states if s.state_type == "terminal"
            }

            for trans in body.transitions:
                if trans.from_state_name not in state_id_map:
                    raise HTTPException(
                        status_code=400,
                        detail=f"transition references non-existent state: {trans.from_state_name}",
                    )
                if trans.to_state_name not in state_id_map:
                    raise HTTPException(
                        status_code=400,
                        detail=f"transition references non-existent state: {trans.to_state_name}",
                    )

                if trans.from_state_name in terminal_state_names:
                    raise HTTPException(
                        status_code=400,
                        detail=f"transitions from terminal state '{trans.from_state_name}' are not allowed",
                    )

                from_id = state_id_map[trans.from_state_name]
                to_id = state_id_map[trans.to_state_name]

                await db.execute(
                    """
                    INSERT INTO sm_transitions 
                    (state_machine_id, from_state_id, to_state_id, trigger_field, trigger_value, direction_constraint)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        state_machine_id,
                        from_id,
                        to_id,
                        trans.trigger_field,
                        trans.trigger_value,
                        trans.direction_constraint,
                    ),
                )

        await db.commit()

        sm_row = (await db.execute_fetchall(
            "SELECT * FROM state_machines WHERE id = ?", (state_machine_id,)
        ))[0]

        state_rows = await db.execute_fetchall(
            "SELECT * FROM sm_states WHERE state_machine_id = ? ORDER BY id",
            (state_machine_id,),
        )

        trans_rows = await db.execute_fetchall(
            """
            SELECT t.*, 
                   s_from.name as from_state_name,
                   s_to.name as to_state_name
            FROM sm_transitions t
            JOIN sm_states s_from ON t.from_state_id = s_from.id
            JOIN sm_states s_to ON t.to_state_id = s_to.id
            WHERE t.state_machine_id = ?
            ORDER BY t.id
            """,
            (state_machine_id,),
        )
    finally:
        await db.close()

    return StateMachineDetailOut(
        id=sm_row["id"],
        template_id=sm_row["template_id"],
        name=sm_row["name"],
        description=sm_row["description"] or "",
        states=[_row_to_state_out(r) for r in state_rows],
        transitions=[_row_to_transition_out(r) for r in trans_rows],
        created_at=sm_row["created_at"] or "",
    )


@router.delete("/{state_machine_id}", status_code=204)
async def delete_state_machine(state_machine_id: int):
    await _get_state_machine_or_404(state_machine_id)
    db = await get_db()
    try:
        await db.execute(
            "DELETE FROM state_machines WHERE id = ?", (state_machine_id,)
        )
        await db.commit()
    finally:
        await db.close()
    return None


@router.post("/validate/{session_id}", response_model=ValidationResult)
async def validate_session(session_id: int, state_machine_id: Optional[int] = None):
    db = await get_db()
    try:
        s_rows = await db.execute_fetchall(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        )
        if not s_rows:
            raise HTTPException(status_code=404, detail="session not found")
        session = s_rows[0]

        if state_machine_id is None:
            sm_rows = await db.execute_fetchall(
                "SELECT * FROM state_machines WHERE template_id = ?",
                (session["template_id"],),
            )
            if not sm_rows:
                raise HTTPException(
                    status_code=404,
                    detail="no state machine found for this session's template, specify state_machine_id",
                )
            sm = sm_rows[0]
            state_machine_id = sm["id"]
        else:
            sm_rows = await db.execute_fetchall(
                "SELECT * FROM state_machines WHERE id = ?", (state_machine_id,)
            )
            if not sm_rows:
                raise HTTPException(status_code=404, detail="state machine not found")
            sm = sm_rows[0]
            if sm["template_id"] != session["template_id"]:
                raise HTTPException(
                    status_code=400,
                    detail="state machine template does not match session template",
                )

        state_rows = await db.execute_fetchall(
            "SELECT * FROM sm_states WHERE state_machine_id = ?",
            (state_machine_id,),
        )

        trans_rows = await db.execute_fetchall(
            """
            SELECT t.*, 
                   s_from.name as from_state_name,
                   s_to.name as to_state_name
            FROM sm_transitions t
            JOIN sm_states s_from ON t.from_state_id = s_from.id
            JOIN sm_states s_to ON t.to_state_id = s_to.id
            WHERE t.state_machine_id = ?
            """,
            (state_machine_id,),
        )

        frame_rows = await db.execute_fetchall(
            "SELECT * FROM session_frames WHERE session_id = ? ORDER BY seq ASC",
            (session_id,),
        )
    finally:
        await db.close()

    states_by_id = {s["id"]: s for s in state_rows}
    states_by_name = {s["name"]: s for s in state_rows}

    initial_states = [s for s in state_rows if s["state_type"] == "initial"]
    if not initial_states:
        return ValidationResult(
            session_id=session_id,
            state_machine_id=state_machine_id,
            final_state=None,
            reached_terminal=False,
            can_validate=False,
            violation_count=0,
            violations=[],
            transition_history=[],
            total_frames=len(frame_rows),
        )

    initial_state = initial_states[0]

    transitions_by_from: dict[int, list] = {}
    for t in trans_rows:
        if t["from_state_id"] not in transitions_by_from:
            transitions_by_from[t["from_state_id"]] = []
        transitions_by_from[t["from_state_id"]].append(t)

    current_state_id = initial_state["id"]
    current_state_name = initial_state["name"]
    violations: list[ViolationFrame] = []
    history: list[StateTransitionHistoryEntry] = []
    can_validate = True
    step = 0

    for i, frame_row in enumerate(frame_rows):
        parse_result = _parse_result_from_json(frame_row["parse_result_json"])
        direction = frame_row["direction"]
        seq = frame_row["seq"]

        if i == 0:
            from_trans = transitions_by_from.get(current_state_id, [])
            first_frame_match = False
            for t in from_trans:
                if t["direction_constraint"] not in (direction, "both"):
                    continue
                if parse_result is None:
                    continue
                field_val = None
                for f in parse_result.fields:
                    if f.name == t["trigger_field"]:
                        field_val = f.value
                        break
                if field_val is not None and str(field_val) == str(t["trigger_value"]):
                    first_frame_match = True
                    break
            if not first_frame_match and len(from_trans) > 0:
                can_validate = False

        if not can_validate:
            break

        from_trans = transitions_by_from.get(current_state_id, [])
        matched_trans = None

        if parse_result is not None:
            for t in from_trans:
                if t["direction_constraint"] not in (direction, "both"):
                    continue
                field_val = None
                for f in parse_result.fields:
                    if f.name == t["trigger_field"]:
                        field_val = f.value
                        break
                if field_val is not None and str(field_val) == str(t["trigger_value"]):
                    matched_trans = t
                    break

        if matched_trans is not None:
            step += 1
            history.append(
                StateTransitionHistoryEntry(
                    step=step,
                    from_state=current_state_name,
                    to_state=matched_trans["to_state_name"],
                    frame_seq=seq,
                    trigger_field=matched_trans["trigger_field"],
                    trigger_value=matched_trans["trigger_value"],
                )
            )
            current_state_id = matched_trans["to_state_id"]
            current_state_name = matched_trans["to_state_name"]
        else:
            expected = []
            for t in from_trans:
                expected.append({
                    "to_state": t["to_state_name"],
                    "trigger_field": t["trigger_field"],
                    "trigger_value": t["trigger_value"],
                    "direction_constraint": t["direction_constraint"],
                })

            actual_val = None
            if parse_result is not None and from_trans:
                trigger_field = from_trans[0]["trigger_field"]
                for f in parse_result.fields:
                    if f.name == trigger_field:
                        actual_val = f.value
                        break

            violations.append(
                ViolationFrame(
                    frame_seq=seq,
                    current_state=current_state_name,
                    expected_transitions=expected,
                    actual_field_value=actual_val,
                    actual_direction=direction,
                )
            )

    terminal_state_ids = {
        s["id"] for s in state_rows if s["state_type"] == "terminal"
    }
    reached_terminal = current_state_id in terminal_state_ids

    return ValidationResult(
        session_id=session_id,
        state_machine_id=state_machine_id,
        final_state=current_state_name if can_validate else None,
        reached_terminal=reached_terminal and can_validate,
        can_validate=can_validate,
        violation_count=len(violations),
        violations=violations,
        transition_history=history,
        total_frames=len(frame_rows),
    )


@router.post("/infer/{session_id}", response_model=InferenceResult)
async def infer_state_machine(
    session_id: int,
    template_id: int,
    trigger_field: str = Query(..., description="Field name to use for state transitions"),
):
    db = await get_db()
    try:
        t_rows = await db.execute_fetchall(
            "SELECT * FROM templates WHERE id = ?", (template_id,)
        )
        if not t_rows:
            raise HTTPException(status_code=404, detail="template not found")

        s_rows = await db.execute_fetchall(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        )
        if not s_rows:
            raise HTTPException(status_code=404, detail="session not found")
        session = s_rows[0]

        if session["template_id"] != template_id:
            raise HTTPException(
                status_code=400,
                detail="session template does not match specified template_id",
            )

        frame_rows = await db.execute_fetchall(
            "SELECT * FROM session_frames WHERE session_id = ? ORDER BY seq ASC",
            (session_id,),
        )

        if not frame_rows:
            raise HTTPException(
                status_code=400,
                detail="session has no frames, cannot infer state machine",
            )
    finally:
        await db.close()

    field_values = []
    directions = []
    for frame_row in frame_rows:
        parse_result = _parse_result_from_json(frame_row["parse_result_json"])
        directions.append(frame_row["direction"])
        if parse_result is None:
            field_values.append(None)
            continue
        val = None
        for f in parse_result.fields:
            if f.name == trigger_field:
                val = f.value
                break
        field_values.append(val)

    if all(v is None for v in field_values):
        raise HTTPException(
            status_code=400,
            detail=f"trigger field '{trigger_field}' not found or has no values in session frames",
        )

    state_segments = []
    current_val = None
    current_start = 0

    for i, val in enumerate(field_values):
        if val is None:
            continue
        if current_val is None:
            current_val = val
            current_start = i
        elif val != current_val:
            state_segments.append({
                "value": current_val,
                "start_idx": current_start,
                "end_idx": i - 1,
                "direction": directions[current_start],
            })
            current_val = val
            current_start = i

    if current_val is not None:
        state_segments.append({
            "value": current_val,
            "start_idx": current_start,
            "end_idx": len(field_values) - 1,
            "direction": directions[current_start],
        })

    if len(state_segments) > MAX_STATES:
        raise HTTPException(
            status_code=400,
            detail=f"inferred states ({len(state_segments)}) exceed maximum of {MAX_STATES}, try a different trigger field",
        )

    states: list[CandidateState] = []
    for i, seg in enumerate(state_segments):
        if i == 0:
            state_type = "initial"
        elif i == len(state_segments) - 1:
            state_type = "terminal"
        else:
            state_type = "intermediate"

        state_name = f"state_{i}_{seg['value']}"
        states.append(
            CandidateState(
                name=state_name,
                state_type=state_type,
                trigger_field_value=str(seg["value"]),
            )
        )

    transitions: list[CandidateTransition] = []
    for i in range(len(state_segments) - 1):
        from_seg = state_segments[i]
        to_seg = state_segments[i + 1]
        from_name = f"state_{i}_{from_seg['value']}"
        to_name = f"state_{i + 1}_{to_seg['value']}"

        trans_idx = to_seg["start_idx"]
        direction = directions[trans_idx] if trans_idx < len(directions) else "both"

        transitions.append(
            CandidateTransition(
                from_state_name=from_name,
                to_state_name=to_name,
                trigger_field=trigger_field,
                trigger_value=str(to_seg["value"]),
                direction_constraint=direction,
            )
        )

    unique_transitions = []
    seen = set()
    for t in transitions:
        key = (t.from_state_name, t.to_state_name, t.trigger_field, t.trigger_value)
        if key not in seen:
            seen.add(key)
            unique_transitions.append(t)

    if len(unique_transitions) > MAX_TRANSITIONS:
        raise HTTPException(
            status_code=400,
            detail=f"inferred transitions ({len(unique_transitions)}) exceed maximum of {MAX_TRANSITIONS}",
        )

    return InferenceResult(
        session_id=session_id,
        template_id=template_id,
        trigger_field=trigger_field,
        states=states,
        transitions=unique_transitions,
        total_frames=len(frame_rows),
        status="candidate",
    )
