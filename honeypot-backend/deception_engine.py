
def select_decoy(alert):
    """
    Select a predefined, simulated decoy response.
    Does not open ports, launch services, or execute commands.
    """

    reasons = alert.reasons or []
    reason_text = " ".join(str(reason).lower() for reason in reasons)

    if "rapid" in reason_text or "port" in reason_text:
        return {
            "selected_decoy": "http_service",
            "response_type": "simulated_http_banner",
            "decision_reason": (
                "Port-scanning evidence detected; selected "
                "a simulated HTTP service response."
            ),
            "simulated_response": {
                "status_code": 200,
                "server_banner": "Example-Decoy/1.0",
                "body": "Simulated service information.",
                "simulation_only": True,
            },
        }

    if alert.severity == "HIGH":
        return {
            "selected_decoy": "generic_high_interaction",
            "response_type": "simulated_generic_response",
            "decision_reason": (
                "High-severity alert; selected a generic "
                "simulated decoy response."
            ),
            "simulated_response": {
                "message": "Simulated decoy response.",
                "simulation_only": True,
            },
        }

    return {
        "selected_decoy": "generic_service",
        "response_type": "simulated_generic_response",
        "decision_reason": (
            "No specialized rule matched; selected the "
            "default simulated response."
        ),
        "simulated_response": {
            "message": "Generic simulated service response.",
            "simulation_only": True,
        },
    }
