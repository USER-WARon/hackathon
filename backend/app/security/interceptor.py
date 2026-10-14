from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from app.security.action_classifier import classify_action, detect_suspicious_content
from app.security.audit import AuditLogger
from app.security.approvals import ApprovalManager
from app.security.intent_guard import check_intent
from app.security.ml_models import MLModelRuntime
from app.security.registry import TrustRegistry
from app.security.response_guard import ResponseGuard
from app.security.response_synthesizer import synthesize_error, synthesize_pending
from app.security.risk_engine import analyze_sql
from app.security.shadow_state import ShadowStateManager, SimulationResult
from app.security.taint import TaintEngine


class ShadowGuardInterceptor:
    def __init__(
        self,
        db_path: str,
        trust_registry: TrustRegistry,
        taint_engine: TaintEngine,
        shadow_state: ShadowStateManager,
        approval_manager: ApprovalManager,
        audit_logger: AuditLogger,
        event_hub: Any,
        raw_tools: dict[str, Any],
        ml_models: MLModelRuntime | None = None,
    ):
        self.db_path = db_path
        self.trust_registry = trust_registry
        self.taint_engine = taint_engine
        self.shadow_state = shadow_state
        self.approval_manager = approval_manager
        self.audit_logger = audit_logger
        self.event_hub = event_hub
        self.raw_tools = raw_tools
        self.ml_models = ml_models if ml_models is not None else getattr(trust_registry, 'ml_models', None)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _emit(
        self,
        event_type: str,
        session_id: str,
        summary: str,
        details: dict[str, Any] | None = None,
        action_id: str | None = None,
        tool_name: str | None = None,
        policy_code: str | None = None,
        request_id: str | None = None,
        severity: str = 'info',
    ) -> None:
        if self.event_hub:
            self.event_hub.publish(
                event_type, session_id, summary,
                details or {}, action_id, tool_name, policy_code,
                request_id=request_id, severity=severity,
            )

    def _log(
        self,
        event_type: str,
        session_id: str,
        summary: str,
        details: dict[str, Any] | None = None,
        action_id: str | None = None,
        tool_name: str | None = None,
        policy_code: str | None = None,
        request_id: str | None = None,
        severity: str = 'info',
    ) -> None:
        self.audit_logger.log_event(
            event_type, session_id, summary,
            details, action_id, tool_name, policy_code,
            request_id=request_id, severity=severity,
        )

    def _record_provenance(
        self,
        session_id: str,
        tool_name: str,
        tool_call_id: str,
        status: str,
        argument_fields: set[str],
        inherited_sources: list[dict[str, Any]],
        result_fields: set[str] | None = None,
        action_id: str | None = None,
        policy_code: str | None = None,
        message: str | None = None,
        guidance: str | None = None,
        request_id: str | None = None,
    ) -> None:
        details = {
            'tool_name': tool_name,
            'tool_call_id': tool_call_id,
            'status': status,
            'argument_fields': sorted(argument_fields),
            'result_fields': sorted(result_fields or set()),
            'inherited_sources': inherited_sources,
            'action_id': action_id,
        }
        if policy_code:
            details['policy_code'] = policy_code
        if message:
            details['message'] = message
        if guidance:
            details['guidance'] = guidance
        self._log(
            'tool_call_provenance',
            session_id,
            f'{tool_name} tool call {status}',
            details,
            action_id,
            tool_name,
            policy_code,
            request_id=request_id,
        )

    # ------------------------------------------------------------------
    # Public execute
    # ------------------------------------------------------------------

    def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        session_id: str | None = None,
        user_id: str = 'demo-user',
        tool_call_id: str | None = None,
        request_id: str | None = None,
        user_objective: str = '',
        authorized_capabilities: list[str] | None = None,
    ) -> dict[str, Any]:
        arguments = arguments or {}
        authorized_capabilities = (
            authorized_capabilities
            if authorized_capabilities is not None
            else ['read', 'write', 'delete']
        )
        session_id = self.taint_engine.get_or_create_session(session_id, user_id)
        tool_call_id = tool_call_id or str(uuid.uuid4())
        argument_fields = set(arguments)
        inherited_sources = self.taint_engine.get_sources(session_id)

        # ---- TOOL_CALL_PROPOSED ------------------------------------------
        self._log(
            'TOOL_CALL_PROPOSED', session_id,
            f'Agent proposed {tool_name}',
            {'tool_name': tool_name, 'argument_fields': sorted(argument_fields),
             'authorized_capabilities': authorized_capabilities},
            None, tool_name, None,
            request_id=request_id, severity='info',
        )

        # ---- TOOL_IDENTITY_VALIDATED / UNKNOWN_TOOL -----------------------
        tool = self.trust_registry.get_tool(tool_name)
        if tool is None:
            summary = f'Unknown tool attempted: {tool_name}'
            self._record_provenance(
                session_id, tool_name, tool_call_id, 'blocked',
                argument_fields, inherited_sources,
                policy_code='UNKNOWN_TOOL',
                message='The requested tool is not registered in the gateway.',
                guidance='Ask the administrator to register the tool or use a supported integration.',
                request_id=request_id,
            )
            self._log('security_error', session_id, summary,
                      {'tool_name': tool_name}, None, tool_name, 'UNKNOWN_TOOL',
                      request_id=request_id, severity='error')
            self._emit('security_error', session_id, summary,
                       {'tool_name': tool_name}, None, tool_name, 'UNKNOWN_TOOL',
                       request_id=request_id, severity='error')
            return synthesize_error(
                'UNKNOWN_TOOL',
                'The requested tool is not registered in the gateway.',
                'Ask the administrator to register the tool or use a supported integration.',
            )

        if not tool['enabled']:
            summary = f'Disabled tool attempted: {tool_name}'
            self._record_provenance(
                session_id, tool_name, tool_call_id, 'blocked',
                argument_fields, inherited_sources,
                policy_code='TOOL_DISABLED',
                message='The requested integration is disabled.',
                guidance='Use an enabled integration or ask the administrator to enable it.',
                request_id=request_id,
            )
            self._log('security_error', session_id, summary,
                      {'tool_name': tool_name}, None, tool_name, 'TOOL_DISABLED',
                      request_id=request_id, severity='error')
            self._emit('security_error', session_id, summary,
                       {'tool_name': tool_name}, None, tool_name, 'TOOL_DISABLED',
                       request_id=request_id, severity='error')
            return synthesize_error(
                'TOOL_DISABLED',
                'The requested integration is disabled.',
                'Use an enabled integration or ask the administrator to enable it.',
            )

        # ---- INTENT_AUTHORIZATION_EVALUATED -------------------------------
        classification = classify_action(tool_name, arguments, tool)
        intent_result = check_intent(
            tool_name,
            arguments,
            authorized_capabilities,
            user_objective,
            ml_classifier=self.ml_models,
            proposed_action=classification,
            taint_state=self.taint_engine.current_state(session_id),
            taint_source_count=len(inherited_sources),
        )
        ml_intent = intent_result['ml_intent']
        safe_intent_details = {
            'tool_name': tool_name,
            'allowed': intent_result['allowed'],
            'required_capability': intent_result.get('required_capability'),
            'authorized_capabilities': authorized_capabilities,
            'classification': ml_intent['classification'],
            'confidence': ml_intent.get('confidence'),
            'reason_codes': ml_intent.get('reason_codes', []),
            'action_category': classification.get('operation'),
            'target_resource': classification.get('target_resource'),
        }
        self._log(
            'INTENT_AUTHORIZATION_EVALUATED', session_id,
            f'Intent check for {tool_name}: {"allowed" if intent_result["allowed"] else "denied"}; ML {ml_intent["classification"]}',
            {
                'argument_fields': sorted(argument_fields),
                'intent_result': intent_result,
                'user_objective_snippet': user_objective[:120],
                'action_category': classification.get('operation'),
                'target_resource': classification.get('target_resource'),
            },
            None, tool_name,
            None if intent_result['allowed'] else 'INTENT_SCOPE_VIOLATION',
            request_id=request_id,
            severity='info' if intent_result['allowed'] else 'warning',
        )
        self._emit(
            'intent_evaluated', session_id,
            f'Intent evaluation for {tool_name}: {ml_intent["classification"]}',
            safe_intent_details, None, tool_name,
            None if intent_result['allowed'] else 'INTENT_SCOPE_VIOLATION',
            request_id=request_id,
            severity='info' if intent_result['allowed'] else 'warning',
        )
        if not intent_result['allowed']:
            self._record_provenance(
                session_id, tool_name, tool_call_id, 'blocked',
                argument_fields, inherited_sources,
                policy_code='INTENT_SCOPE_VIOLATION',
                message=intent_result['reason'],
                guidance=(
                    'Restart the request with the correct authorized_capabilities, '
                    'or ask the user to explicitly authorize this operation.'
                ),
                request_id=request_id,
            )
            self._emit(
                'security_error', session_id,
                'Intent scope violation',
                safe_intent_details | {
                    'argument_fields': sorted(argument_fields),
                    'policy_reasons': [intent_result.get('reason', '')],
                },
                None, tool_name, 'INTENT_SCOPE_VIOLATION',
                request_id=request_id, severity='warning',
            )
            return synthesize_error(
                'INTENT_SCOPE_VIOLATION',
                intent_result['reason'],
                (
                    'The original request only authorized: '
                    + ', '.join(intent_result.get('authorized_capabilities', ['read']))
                    + '. Ask the user to explicitly authorize a broader operation.'
                ),
            )

        if ml_intent['classification'] == 'POTENTIALLY_UNINTENDED':
            message = 'The proposed action appears misaligned with the original request and was not run.'
            guidance = 'Confirm the intended target and operation, then submit a request that explicitly describes them.'
            self._record_provenance(
                session_id, tool_name, tool_call_id, 'blocked',
                argument_fields, inherited_sources,
                policy_code='ML_INTENT_SCOPE_MISMATCH',
                message=message,
                guidance=guidance,
                request_id=request_id,
            )
            details = safe_intent_details | {'argument_fields': sorted(argument_fields)}
            self._log(
                'ML_INTENT_BLOCKED', session_id, message, details,
                None, tool_name, 'ML_INTENT_SCOPE_MISMATCH',
                request_id=request_id, severity='warning',
            )
            self._emit(
                'security_error', session_id, message, details,
                None, tool_name, 'ML_INTENT_SCOPE_MISMATCH',
                request_id=request_id, severity='warning',
            )
            return synthesize_error('ML_INTENT_SCOPE_MISMATCH', message, guidance)

        # ---- TRUST_EVALUATED ----------------------------------------------
        trust_evaluation = self.trust_registry.evaluate_trust(tool)
        effective_tool_zone = (
            'LOW'
            if trust_evaluation['classification'] == 'LOW_TRUST'
            else tool['trust_zone']
        )
        self._log(
            'TRUST_EVALUATED', session_id,
            f'Trust evaluated for {tool_name}: {trust_evaluation["classification"]}',
            {
                'tool_name': tool_name,
                'score': trust_evaluation['score'],
                'weighted_trust_score': trust_evaluation['weighted_trust_score'],
                'ml_trust_score': trust_evaluation['ml_trust_score'],
                'combined_trust_score': trust_evaluation['combined_trust_score'],
                'ml_classification': trust_evaluation['ml_classification'],
                'classification': trust_evaluation['classification'],
                'configured_trust_zone': tool['trust_zone'],
                'effective_tool_trust_zone': effective_tool_zone,
                'reason_codes': trust_evaluation['reason_codes'],
                'mandatory_checks_passed': trust_evaluation['mandatory_checks_passed'],
                'mandatory_override': trust_evaluation['mandatory_override'],
                'hard_deny': trust_evaluation['hard_deny'],
                'reason': trust_evaluation['reason'],
            },
            None, tool_name, None,
            request_id=request_id, severity='info',
        )
        trust_event_details = {
            'tool_name': tool_name,
            'weighted_trust_score': trust_evaluation['weighted_trust_score'],
            'ml_trust_score': trust_evaluation['ml_trust_score'],
            'combined_trust_score': trust_evaluation['combined_trust_score'],
            'ml_classification': trust_evaluation['ml_classification'],
            'classification': trust_evaluation['classification'],
            'configured_trust_zone': tool['trust_zone'],
            'effective_tool_trust_zone': effective_tool_zone,
            'reason_codes': trust_evaluation['reason_codes'],
            'mandatory_checks_passed': trust_evaluation['mandatory_checks_passed'],
            'mandatory_override': trust_evaluation['mandatory_override'],
            'hard_deny': trust_evaluation['hard_deny'],
        }
        self._emit(
            'trust_evaluated', session_id,
            f'Trust evaluated for {tool_name}: {trust_evaluation["classification"]}',
            trust_event_details, None, tool_name,
            'MANDATORY_SECURITY_OVERRIDE' if trust_evaluation['mandatory_override'] else None,
            request_id=request_id, severity='warning' if trust_evaluation['mandatory_override'] else 'info',
        )
        if trust_evaluation['hard_deny']:
            summary = f'Hard-deny policy blocked {tool_name}: {trust_evaluation["reason"]}'
            self._record_provenance(
                session_id, tool_name, tool_call_id, 'blocked',
                argument_fields, inherited_sources,
                policy_code='HARD_DENY',
                message=summary,
                guidance='This policy cannot be overridden by approval.',
                request_id=request_id,
            )
            self._log('security_error', session_id, summary,
                      {'tool_name': tool_name, 'trust': trust_evaluation},
                      None, tool_name, 'HARD_DENY',
                      request_id=request_id, severity='error')
            self._emit('security_error', session_id, summary,
                       {'tool_name': tool_name}, None, tool_name, 'HARD_DENY',
                       request_id=request_id, severity='error')
            return synthesize_error('HARD_DENY', summary, 'This policy cannot be overridden by approval.')

        # ---- ARGUMENTS_VALIDATED / POLICY_DECISION ------------------------
        # Full policy details for the audit log (backend-only, acceptable for forensics).
        policy_details = {
            'tool_name': tool_name,
            'arguments': arguments,
            'trust_score': trust_evaluation['score'],
            'trust_classification': trust_evaluation['classification'],
            'trust_evaluation': trust_evaluation,
            'intent_evaluation': ml_intent,
            'action_classification': classification,
        }
        # Safe subset for the WebSocket event stream.
        policy_details_safe = {
            'tool_name': tool_name,
            'argument_fields': sorted(arguments),
            'trust_score': trust_evaluation['score'],
            'trust_classification': trust_evaluation['classification'],
            'weighted_trust_score': trust_evaluation['weighted_trust_score'],
            'ml_trust_score': trust_evaluation['ml_trust_score'],
            'combined_trust_score': trust_evaluation['combined_trust_score'],
            'trust_reason_codes': trust_evaluation['reason_codes'],
            'mandatory_override': trust_evaluation['mandatory_override'],
            'intent_classification': ml_intent['classification'],
            'intent_confidence': ml_intent.get('confidence'),
            'intent_reason_codes': ml_intent.get('reason_codes', []),
            'policy_reasons': classification.get('reasons', []),
        }

        self._log(
            'POLICY_DECISION', session_id,
            f'Policy decision for {tool_name}: {classification["classification"]}',
            policy_details, None, tool_name, None,
            request_id=request_id, severity='info',
        )

        if classification['classification'] == 'PROHIBITED':
            message = 'This action is prohibited by deterministic gateway policy.'
            guidance = '; '.join(classification['reasons']) or 'Use an authorized resource and destination.'
            self._record_provenance(
                session_id, tool_name, tool_call_id, 'blocked',
                argument_fields, inherited_sources,
                policy_code='ACTION_PROHIBITED', message=message, guidance=guidance,
                request_id=request_id,
            )
            self._log('security_error', session_id, message, policy_details,
                      None, tool_name, 'ACTION_PROHIBITED',
                      request_id=request_id, severity='warning')
            self._emit('security_error', session_id, message, policy_details_safe,
                       None, tool_name, 'ACTION_PROHIBITED',
                       request_id=request_id, severity='warning')
            return synthesize_error('ACTION_PROHIBITED', message, guidance)

        if classification['classification'] == 'IRREVERSIBLE_OR_UNCERTAIN':
            action = self.approval_manager.create_pending(
                session_id, user_id, tool_name,
                arguments.get('sql', '') if tool_name == 'production_database' else '',
                {
                    'allowed': True,
                    'simulation_status': SimulationResult.UNSUPPORTED,
                    'action_type': classification['operation'],
                    'severity': 'high',
                    'classification': classification['classification'],
                    'policy_reasons': classification['reasons'],
                    'suspicious_content': classification['suspicious_content'],
                    'rollback_supported': classification['rollback_supported'],
                },
                arguments=arguments,
                operation=classification['operation'],
                target_resource=classification['target_resource'],
                destination_mcp=classification['destination_mcp'],
                permitted_capabilities=[classification['capability']],
                request_id=request_id,
                user_objective=user_objective,
            )
            message = 'This irreversible or uncertain action is awaiting explicit approval. It has not run.'
            self._record_provenance(
                session_id, tool_name, tool_call_id, 'pending_approval',
                argument_fields, inherited_sources,
                action_id=action['approval_id'],
                policy_code='IRREVERSIBLE_APPROVAL_REQUIRED',
                message=message,
                guidance='Review the exact operation, arguments, destination and expected consequences.',
                request_id=request_id,
            )
            self._log('APPROVAL_STAGED', session_id, message,
                      policy_details | {'approval_id': action['approval_id']},
                      action['approval_id'], tool_name, 'IRREVERSIBLE_APPROVAL_REQUIRED',
                      request_id=request_id, severity='warning')
            self._emit('approval_required', session_id, message,
                       policy_details_safe | {'approval_id': action['approval_id']},
                       action['approval_id'], tool_name, 'IRREVERSIBLE_APPROVAL_REQUIRED',
                       request_id=request_id, severity='warning')
            return synthesize_pending(action['approval_id'], action['approval_id'], message, policy_details_safe)

        # ---- PROVENANCE_EVALUATED -----------------------------------------
        allowed, code = self.taint_engine.can_access_tool(session_id, effective_tool_zone)
        taint_state = self.taint_engine.current_state(session_id)
        self._log(
            'PROVENANCE_EVALUATED', session_id,
            f'Taint check for {tool_name}: {"allowed" if allowed else "blocked"} (session {taint_state})',
            {
                'tool_name': tool_name,
                'session_taint_state': taint_state,
                'taint_sources': inherited_sources,
                'tool_trust_zone': effective_tool_zone,
                'configured_tool_trust_zone': tool['trust_zone'],
                'allowed': allowed,
                'code': code,
            },
            None, tool_name, code,
            request_id=request_id,
            severity='info' if allowed else 'warning',
        )

        if not allowed:
            if tool_name == 'production_database' and tool_name in self.raw_tools:
                sql = arguments.get('sql', '')
                risk = analyze_sql(sql)
                if not risk['allowed']:
                    message = 'This database action is blocked by the ShadowGuard SQL policy.'
                    guidance = '; '.join(risk['reasons']) or 'Change the SQL to an allowed single statement and try again.'
                    self._record_provenance(
                        session_id, tool_name, tool_call_id, 'blocked',
                        argument_fields, inherited_sources,
                        policy_code='SQL_POLICY_BLOCK', message=message, guidance=guidance,
                        request_id=request_id,
                    )
                    self._log('security_error', session_id, f'SQL rejected by policy: {sql[:120]}',
                              {'sql': sql, 'reasons': risk['reasons']},
                              None, tool_name, 'SQL_POLICY_BLOCK',
                              request_id=request_id, severity='warning')
                    self._emit('security_error', session_id, message,
                               {'sql_rejected': True, 'reasons': risk['reasons']},
                               None, tool_name, 'SQL_POLICY_BLOCK',
                               request_id=request_id, severity='warning')
                    return synthesize_error('SQL_POLICY_BLOCK', message, guidance)

                if risk['destructive']:
                    simulation = self._run_simulation(sql, session_id, tool_name, request_id)
                    if simulation is None:
                        return synthesize_error(
                            'SIMULATION_FAILED',
                            'Simulation of the proposed statement failed. The action cannot proceed.',
                            'Inspect the SQL and retry.',
                        )
                    action = self.approval_manager.create_pending(
                        session_id, user_id, tool_name, sql, simulation,
                        arguments=arguments,
                        taint_override_required=True,
                        taint_sources=inherited_sources,
                        operation=classification['operation'],
                        target_resource=classification['target_resource'],
                        destination_mcp=classification['destination_mcp'],
                        permitted_capabilities=[classification['capability']],
                        request_id=request_id,
                        user_objective=user_objective,
                    )
                    message = 'This protected action is awaiting your approval because the session contains untrusted data. It has not run.'
                    self._record_provenance(
                        session_id, tool_name, tool_call_id, 'pending_approval',
                        argument_fields, inherited_sources,
                        set(simulation), action['approval_id'],
                        policy_code='TAINT_OVERRIDE_REQUIRED',
                        message=message,
                        guidance='Review the exact action and taint sources before approving or rejecting it.',
                        request_id=request_id,
                    )
                    self._log('APPROVAL_STAGED', session_id,
                              f'Taint override approval required for {tool_name}',
                              {
                                  'approval_id': action['approval_id'],
                                  'tool_name': tool_name,
                                  'argument_fields': sorted(argument_fields),
                                  'inherited_sources': inherited_sources,
                              },
                              action['approval_id'], tool_name, 'TAINT_OVERRIDE_REQUIRED',
                              request_id=request_id, severity='warning')
                    self._emit('approval_required', session_id, message,
                               {
                                   'approval_id': action['approval_id'],
                                   'tool_name': tool_name,
                                   'argument_fields': sorted(argument_fields),
                                   'inherited_sources': inherited_sources,
                               },
                               action['approval_id'], tool_name, 'TAINT_OVERRIDE_REQUIRED',
                               request_id=request_id, severity='warning')
                    return synthesize_pending(
                        action['approval_id'], action['approval_id'], message, simulation,
                    )

            if tool_name in {'github_reader'} and tool_name in self.raw_tools:
                sim_stub = {
                    'simulation_status': SimulationResult.UNSUPPORTED,
                    'action_type': 'tool_call',
                    'tool_name': tool_name,
                    'arguments': arguments,
                    'severity': 'review',
                }
                action = self.approval_manager.create_pending(
                    session_id, user_id, tool_name, '', sim_stub,
                    arguments=arguments,
                    taint_override_required=True,
                    taint_sources=inherited_sources,
                    operation=classification['operation'],
                    target_resource=classification['target_resource'],
                    destination_mcp=classification['destination_mcp'],
                    permitted_capabilities=[classification['capability']],
                    request_id=request_id,
                    user_objective=user_objective,
                )
                message = 'This protected action is awaiting your approval because the session contains untrusted data. It has not run.'
                self._record_provenance(
                    session_id, tool_name, tool_call_id, 'pending_approval',
                    argument_fields, inherited_sources,
                    set(sim_stub), action['approval_id'],
                    policy_code='TAINT_OVERRIDE_REQUIRED',
                    message=message,
                    guidance='Review the exact action and taint sources before approving or rejecting it.',
                    request_id=request_id,
                )
                self._log('APPROVAL_STAGED', session_id,
                          f'Taint override approval required for {tool_name}',
                          {
                              'approval_id': action['approval_id'],
                              'tool_name': tool_name,
                              'argument_fields': sorted(argument_fields),
                              'inherited_sources': inherited_sources,
                          },
                          action['approval_id'], tool_name, 'TAINT_OVERRIDE_REQUIRED',
                          request_id=request_id, severity='warning')
                self._emit('approval_required', session_id, message,
                           {
                               'approval_id': action['approval_id'],
                               'tool_name': tool_name,
                               'argument_fields': sorted(argument_fields),
                               'inherited_sources': inherited_sources,
                           },
                           action['approval_id'], tool_name, 'TAINT_OVERRIDE_REQUIRED',
                           request_id=request_id, severity='warning')
                return synthesize_pending(
                    action['approval_id'], action['approval_id'], message, sim_stub,
                )

            summary = f'Security block: {tool_name} denied for tainted session {session_id}'
            message = 'This protected action was blocked because the session contains untrusted data.'
            guidance = 'The action was not run. Use a supported integration or start a separate clean session.'
            self._record_provenance(
                session_id, tool_name, tool_call_id, 'blocked',
                argument_fields, inherited_sources,
                policy_code=code or 'TAINTED_HIGH_TRUST_BLOCK',
                message=message, guidance=guidance,
                request_id=request_id,
            )
            self._log('taint_blocked', session_id, summary,
                      {'tool_name': tool_name}, None, tool_name, code,
                      request_id=request_id, severity='warning')
            self._emit('taint_blocked', session_id, summary,
                       {'tool_name': tool_name}, None, tool_name, code,
                       request_id=request_id, severity='warning')
            return synthesize_error(code or 'TAINTED_HIGH_TRUST_BLOCK', message, guidance)

        # ---- Production database path: SQL analysis -----------------------
        if tool_name == 'production_database':
            sql = arguments.get('sql', '')
            risk = analyze_sql(sql)
            if not risk['allowed']:
                summary = f'SQL rejected by policy: {sql[:120]}'
                message = 'This database action is blocked by the ShadowGuard SQL policy.'
                guidance = '; '.join(risk['reasons']) or 'Change the SQL to an allowed single statement and try again.'
                self._record_provenance(
                    session_id, tool_name, tool_call_id, 'blocked',
                    argument_fields, inherited_sources,
                    policy_code='SQL_POLICY_BLOCK', message=message, guidance=guidance,
                    request_id=request_id,
                )
                self._log('security_error', session_id, summary,
                          {'sql': sql, 'reasons': risk['reasons']},
                          None, tool_name, 'SQL_POLICY_BLOCK',
                          request_id=request_id, severity='warning')
                self._emit('security_error', session_id, summary,
                           {'sql_rejected': True, 'reasons': risk['reasons']},
                           None, tool_name, 'SQL_POLICY_BLOCK',
                           request_id=request_id, severity='warning')
                return synthesize_error('SQL_POLICY_BLOCK', message, guidance)

            if risk['destructive']:
                # ---- SANDBOX_STARTED / SIMULATION_COMPLETED ---------------
                simulation = self._run_simulation(sql, session_id, tool_name, request_id)
                if simulation is None:
                    return synthesize_error(
                        'SIMULATION_FAILED',
                        'Simulation of the proposed statement failed. The action cannot proceed.',
                        'Inspect the SQL and retry.',
                    )
                action = self.approval_manager.create_pending(
                    session_id, user_id, tool_name, sql, simulation,
                    arguments=arguments,
                    operation=classification['operation'],
                    target_resource=classification['target_resource'],
                    destination_mcp=classification['destination_mcp'],
                    permitted_capabilities=[classification['capability']],
                    request_id=request_id,
                    user_objective=user_objective,
                )
                self._record_provenance(
                    session_id, tool_name, tool_call_id, 'pending_approval',
                    argument_fields, inherited_sources,
                    set(simulation), action['approval_id'],
                    request_id=request_id,
                )
                self._log('APPROVAL_STAGED', session_id,
                          f'Approval required for {tool_name}',
                          {'approval_id': action['approval_id'], 'sql': sql},
                          action['approval_id'], tool_name, 'APPROVAL_REQUIRED',
                          request_id=request_id, severity='warning')
                blast_radius_safe = {
                    k: v for k, v in simulation.items()
                    if k not in ('before', 'after', 'snapshot_fingerprint')
                }
                self._emit('approval_required', session_id,
                           'Approval required for destructive database action.',
                           {'approval_id': action['approval_id'], 'blast_radius': blast_radius_safe},
                           action['approval_id'], tool_name, 'APPROVAL_REQUIRED',
                           request_id=request_id, severity='warning')
                return synthesize_pending(
                    action['approval_id'], action['approval_id'],
                    'Destructive SQL requires human approval before execution.',
                    simulation,
                )

        if tool_name not in self.raw_tools:
            self._record_provenance(
                session_id, tool_name, tool_call_id, 'blocked',
                argument_fields, inherited_sources,
                policy_code='UNSUPPORTED_TOOL',
                message='Tool exists but lacks a registered implementation.',
                guidance='Use the supported gateway toolset only.',
                request_id=request_id,
            )
            return synthesize_error(
                'UNSUPPORTED_TOOL',
                'Tool exists but lacks a registered implementation.',
                'Use the supported gateway toolset only.',
            )

        # ---- MCP_TOOL_INVOKED / MCP_RESPONSE_RECEIVED ---------------------
        self._log('MCP_TOOL_INVOKED', session_id, f'Executing {tool_name}',
                  {'tool_name': tool_name, 'argument_fields': sorted(argument_fields)},
                  None, tool_name, None,
                  request_id=request_id, severity='info')

        raw_result = self.raw_tools[tool_name](**arguments)

        # ---- RESPONSE_VALIDATED (ResponseGuard) --------------------------
        guarded = ResponseGuard.inspect_response(tool_name, tool, raw_result)
        result = guarded.sanitized_data

        if guarded.redacted_secrets_count > 0:
            self._log('secret_leak_detected', session_id,
                      f'Redacted {guarded.redacted_secrets_count} credential pattern(s) from {tool_name} output',
                      {'tool_name': tool_name, 'redacted_count': guarded.redacted_secrets_count},
                      None, tool_name, 'SECRET_REDACTED',
                      request_id=request_id, severity='warning')
            self._emit('secret_leak_detected', session_id,
                       f'Redacted credentials from {tool_name} response.',
                       {'tool_name': tool_name, 'redacted_count': guarded.redacted_secrets_count},
                       None, tool_name, 'SECRET_REDACTED',
                       request_id=request_id, severity='warning')

        if guarded.suspicious_patterns:
            self._log('suspicious_content_detected', session_id,
                      'Retrieved content contains suspicious links or prompt-injection patterns',
                      {'tool_name': tool_name, 'patterns': guarded.suspicious_patterns},
                      None, tool_name, 'SUSPICIOUS_CONTENT',
                      request_id=request_id, severity='warning')
            self._emit('suspicious_content_detected', session_id,
                       'Retrieved content contains suspicious links or prompt-injection patterns.',
                       {'tool_name': tool_name, 'patterns': guarded.suspicious_patterns},
                       None, tool_name, 'SUSPICIOUS_CONTENT',
                       request_id=request_id, severity='warning')

        tool_result_fields = list(raw_result) if isinstance(raw_result, dict) else list(result)
        if effective_tool_zone == 'LOW' and result.get('status') != 'error' and not result.get('isError'):
            self.taint_engine.mark_tainted(session_id, tool_name, tool_call_id, tool_result_fields)
            self._log('taint_updated', session_id,
                      'Session tainted by low-trust tool result',
                      {'source_tool': tool_name, 'tool_call_id': tool_call_id,
                       'affected_fields': sorted(tool_result_fields)},
                      None, tool_name, 'TAINTED',
                      request_id=request_id, severity='info')
            self._emit('taint_updated', session_id,
                       'Session tainted by low-trust tool result.',
                       {'source_tool': tool_name},
                       None, tool_name, 'TAINTED',
                       request_id=request_id, severity='info')

        final_status = 'failed' if result.get('isError') or result.get('status') == 'error' else 'executed'
        tool_result_fields = set(raw_result) if isinstance(raw_result, dict) else set(result)
        self._record_provenance(
            session_id, tool_name, tool_call_id, final_status,
            argument_fields, inherited_sources, tool_result_fields,
            request_id=request_id,
        )
        self._log('tool_call_allowed', session_id,
                  f'{tool_name} executed through ShadowGuard',
                  {'tool_name': tool_name, 'result': result},
                  None, tool_name, None,
                  request_id=request_id, severity='info')
        self._emit('tool_call_allowed', session_id,
                   f'{tool_name} executed through ShadowGuard.',
                   {'tool_name': tool_name, 'result_fields': sorted(result)},
                   None, tool_name, None,
                   request_id=request_id, severity='info')
        return result

    # ------------------------------------------------------------------
    # Simulation helper
    # ------------------------------------------------------------------

    def _run_simulation(
        self,
        sql: str,
        session_id: str,
        tool_name: str,
        request_id: str | None,
    ) -> dict[str, Any] | None:
        """
        Run shadow-state simulation.  Log SANDBOX_STARTED and
        SIMULATION_COMPLETED / SIMULATION_FAILED events.
        Returns the simulation dict on success, None on failure.
        """
        self._log('SANDBOX_STARTED', session_id,
                  f'Starting shadow simulation for {tool_name}',
                  {'tool_name': tool_name},
                  None, tool_name, None,
                  request_id=request_id, severity='info')
        simulation = self.shadow_state.evaluate_statement(sql)
        status = simulation.get('simulation_status')
        if status == 'failed':
            self._log('SIMULATION_COMPLETED', session_id,
                      'Shadow simulation failed — action cannot proceed',
                      {'simulation_error': simulation.get('simulation_error'), 'tool_name': tool_name},
                      None, tool_name, 'SIMULATION_FAILED',
                      request_id=request_id, severity='error')
            self._emit('SIMULATION_COMPLETED', session_id,
                       'Shadow simulation failed.',
                       {'tool_name': tool_name, 'simulation_status': 'failed'},
                       None, tool_name, 'SIMULATION_FAILED',
                       request_id=request_id, severity='error')
            return None
        self._log('SIMULATION_COMPLETED', session_id,
                  f'Shadow simulation complete: {simulation.get("affected_rows")} rows affected',
                  {
                      'tool_name': tool_name,
                      'affected_rows': simulation.get('affected_rows'),
                      'total_rows': simulation.get('total_rows'),
                      'percentage_affected': simulation.get('percentage_affected'),
                      'zero_row_reason': simulation.get('zero_row_reason'),
                      'simulation_status': status,
                  },
                  None, tool_name, None,
                  request_id=request_id, severity='info')
        self._emit('SIMULATION_COMPLETED', session_id,
                   f'Shadow simulation complete.',
                   {
                       'tool_name': tool_name,
                       'affected_rows': simulation.get('affected_rows'),
                       'total_rows': simulation.get('total_rows'),
                       'percentage_affected': simulation.get('percentage_affected'),
                       'simulation_status': status,
                   },
                   None, tool_name, None,
                   request_id=request_id, severity='info')
        return simulation
