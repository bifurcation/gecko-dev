from tests.support.asserts import assert_dialog_handled, assert_error, assert_success
from tests.support.fixtures import create_dialog
from tests.support.inline import inline


def delete_cookie(session, name):
    return session.transport.send(
        "DELETE", "/session/{session_id}/cookie/{name}".format(
            session_id=session.session_id,
            name=name))


def test_no_browsing_context(session, create_window):
    session.window_handle = create_window()
    session.close()

    response = delete_cookie(session, "foo")
    assert_error(response, "no such window")


def test_handle_prompt_dismiss_and_notify():
    """TODO"""


def test_handle_prompt_accept_and_notify():
    """TODO"""


def test_handle_prompt_ignore():
    """TODO"""


def test_handle_prompt_accept(new_session, add_browser_capabilites):
    _, session = new_session({"capabilities": {"alwaysMatch": add_browser_capabilites({"unhandledPromptBehavior": "accept"})}})
    session.url = inline("<title>WD doc title</title>")

    create_dialog(session)("alert", text="dismiss #1", result_var="dismiss1")
    response = delete_cookie(session, "foo")
    assert_success(response)
    assert_dialog_handled(session, "dismiss #1")

    create_dialog(session)("confirm", text="dismiss #2", result_var="dismiss2")
    response = delete_cookie(session, "foo")
    assert_success(response)
    assert_dialog_handled(session, "dismiss #2")

    create_dialog(session)("prompt", text="dismiss #3", result_var="dismiss3")
    response = delete_cookie(session, "foo")
    assert_success(response)
    assert_dialog_handled(session, "dismiss #3")


def test_handle_prompt_missing_value(session, create_dialog):
    session.url = inline("<title>WD doc title</title>")
    create_dialog("alert", text="dismiss #1", result_var="dismiss1")

    response = delete_cookie(session, "foo")
    assert_error(response, "unexpected alert open")
    assert_dialog_handled(session, "dismiss #1")

    create_dialog("confirm", text="dismiss #2", result_var="dismiss2")

    response = delete_cookie(session, "foo")
    assert_error(response, "unexpected alert open")
    assert_dialog_handled(session, "dismiss #2")

    create_dialog("prompt", text="dismiss #3", result_var="dismiss3")

    response = delete_cookie(session, "foo")
    assert_error(response, "unexpected alert open")
    assert_dialog_handled(session, "dismiss #3")


def test_unknown_cookie(session):
    response = delete_cookie(session, "stilton")
    assert_success(response)
