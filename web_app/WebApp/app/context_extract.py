
from fastapi import Request

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

def request_context_extract(request: Request):
    print(">>> request_context_extract CALLED <<<")
    debug_print_request(request)


    return











