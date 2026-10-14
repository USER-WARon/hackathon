from fastapi import APIRouter, HTTPException, Request

from app.schemas import IntegrationSettingsRequest

router = APIRouter(prefix='/api')


@router.get('/integrations')
def list_integrations(request: Request):
    app_state = request.app.state.app_state
    return {'tools': app_state['trust_registry'].list_tools()}


@router.post('/integrations')
def set_integration(request: Request, settings: IntegrationSettingsRequest):
    app_state = request.app.state.app_state
    existing = app_state['trust_registry'].get_tool(settings.name)
    if existing is None:
        raise HTTPException(
            status_code=404,
            detail=f"Integration '{settings.name}' is not registered in the gateway.",
        )

    zone = settings.trust_zone.upper()
    if zone not in {'HIGH', 'LOW', 'MEDIUM'}:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid trust zone '{settings.trust_zone}'. Allowed zones: HIGH, LOW, MEDIUM.",
        )

    try:
        tool = app_state['trust_registry'].set_trust_zone(settings.name, zone)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    trust_details = {
        'tool_name': settings.name,
        'trust_zone': zone,
        'weighted_trust_score': tool.get('weighted_trust_score'),
        'ml_trust_score': tool.get('ml_trust_score'),
        'combined_trust_score': tool.get('combined_trust_score'),
        'ml_classification': tool.get('ml_classification'),
        'trust_classification': tool.get('trust_classification'),
        'trust_reason_codes': tool.get('trust_reason_codes', []),
        'mandatory_override': tool.get('mandatory_override', False),
    }
    request.app.state.audit_logger.log_event(
        'integration_policy_updated',
        'system',
        f"Integration '{settings.name}' trust zone updated to {zone}",
        trust_details,
        None,
        settings.name,
        'POLICY_UPDATE',
        severity='info',
    )
    app_state['event_hub'].publish(
        'integration_policy_updated',
        'system',
        f"Integration '{settings.name}' trust zone updated to {zone}.",
        trust_details,
        None,
        settings.name,
        'POLICY_UPDATE',
    )
    return {'tool': tool}
