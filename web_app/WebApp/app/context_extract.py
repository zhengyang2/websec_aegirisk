
from fastapi import Request
from datetime import datetime, timezone




def debug_print_request(request: Request):
    print("=== REQUEST DEBUG START ===")

    # Basic info
    print("Method:", request.method)
    print("URL:", str(request.url))
    print("Base URL:", str(request.base_url))

    # Client / socket info
    print("Client:", request.client)  # (host, port)

    # Headers
    print("Headers:")
    for k, v in request.headers.items():
        print(f"  {k}: {v}")

    # Cookies
    print("Cookies:")
    for k, v in request.cookies.items():
        print(f"  {k}: {v}")

    # Query params
    print("Query params:", dict(request.query_params))

    print("=== REQUEST DEBUG END ===")

def request_context_extract(request: Request, username):

    #debug_print_request(request)


    ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    device_token = request.cookies.get("__Host_rba_dt")

    timestamp_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


    context = {
        "username": username,
        "event_time_utc": timestamp_utc,
        "ip": ip,
        "user_agent": user_agent,
        "device_token": device_token,
    }



    return context











