import json

from flask import Flask, url_for, session, redirect, request
import globus_sdk
import logging

app = Flask(__name__)
app.config.from_pyfile("app.conf")
CLIENT_ID = "c201d5b3-1837-43a7-ba25-2782493ecaf7"#'4caa596e-7d65-4be9-a1e9-311ec9e20326'  # '411bb93e-a134-4f6d-aac1-e893f1a1b46b'

CLIENT_SECRET = "CjljWaIWNC9TeFDHe8kDll9FBfxSB+uSjFcT9IbC16k="  # 'abGogbXMfwb6KXIkSY0KXDKnIprtcGf6CoqIIMVmjn0='
app.secret_key = 'newsecretid'

logging.basicConfig(level=logging.DEBUG)


def load_app_client():
    return globus_sdk.ConfidentialAppAuthClient(CLIENT_ID, CLIENT_SECRET)


@app.route("/")
def index():

    if not session.get("is_authenticated"):
        return redirect(url_for("login"))
    return "You are successfully logged in!"


@app.route("/login")
def login():

    # the redirect URI, as a complete URI (not relative path)
    redirect_uri = url_for("login", _external=True)

    client = load_app_client()
    client.oauth2_start_flow(redirect_uri)

    # If there's no "code" query string parameter, we're in this route
    # starting a Globus Auth login flow.
    # Redirect out to Globus Auth
    if "code" not in request.args:
        auth_uri = client.oauth2_get_authorize_url()
        return redirect(auth_uri)
    # If we do have a "code" param, we're coming back from Globus Auth
    # and can start the process of exchanging an auth code for a token.
    else:
        code = request.args.get("code")
        tokens = client.oauth2_exchange_code_for_tokens(code)

        # store the resulting tokens in the session
        session.update(tokens=tokens.by_resource_server, is_authenticated=True)
        return redirect(url_for("index"))


@app.route("/logout")
def logout():
    client = load_app_client()

    # Revoke the tokens with Globus Auth
    for token in (
            token_info["access_token"] for token_info in session["tokens"].values()
    ):
        client.oauth2_revoke_token(token)

    # Destroy the session state
    session.clear()

    # the return redirection location to give to Globus AUth
    redirect_uri = url_for("index", _external=True)

    # build the logout URI with query params
    # there is no tool to help build this (yet!)
    globus_logout_url = (
            "https://auth.globus.org/v2/web/logout"
            + "?client={}".format(CLIENT_ID)
            + "&redirect_uri={}".format(redirect_uri)
            + "&redirect_name=Globus Example App"
    )

    # Redirect the user to the Globus Auth logout page
    return redirect(globus_logout_url)

@app.route("/data")
def data():
    # print(session["tokens"]["transfer.api.globus.org"]["access_token"])
    authorizer = globus_sdk.AccessTokenAuthorizer(
        session["tokens"]["transfer.api.globus.org"]["access_token"]
    )
    transfer_client = globus_sdk.TransferClient(authorizer=authorizer)

    print("Endpoints belonging to the current logged-in user:")
    for ep in transfer_client.endpoint_search(filter_scope="my-endpoints"):
        print("[{}] {}".format(ep["id"], ep["display_name"]))

    # Replace these with your own collection UUIDs
    dest_collection_id = "48d744cc-452f-11ef-aded-8f248ba91607"
    source_collection_id = "8d832f28-452f-11ef-8df9-19f3c8361d4f"

    # create a Transfer task consisting of one or more items
    task_data = globus_sdk.TransferData(
        source_endpoint=source_collection_id, destination_endpoint=dest_collection_id
    )
    task_data.add_item(
        "/home/ferroelectric/data",  # source
        "/home/ferroelectric/data",  # dest
    )

    # submit, getting back the task ID
    task_doc = transfer_client.submit_transfer(task_data)
    task_id = task_doc["task_id"]
    print(f"submitted transfer, task_id={task_id}")
    return f"submitted transfer, task_id={task_id}"

if __name__ == "__main__":
    app.run(debug=True)
