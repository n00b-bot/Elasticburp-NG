from doc_HttpRequestResponse import DocHTTPRequestResponse
from elasticsearch_dsl.connections import connections
from elasticsearch_dsl import Index
from datetime import datetime

connections.create_connection(hosts=["localhost"])

idx = Index("test")
idx.doc_type(DocHTTPRequestResponse)
#idx.create()

DocHTTPRequestResponse.init()

d = DocHTTPRequestResponse(
        protocol="http",
        host="foobar.com",
        port=80
        )
d.add_request_header("User-Agent: foobar")
d.add_request_parameter("url", "id", "123")
d.add_request_parameter("url", "doc", "234")
d.add_response_header("X-Content-Type-Options: nosniff")
d.add_response_header("X-Frame-Options: DENY")
d.add_response_header("X-XSS-Protection: 1; mode=block")
d.add_response_cookie("SESSIONID", "foobar1234")
d.add_response_cookie("foo", "bar", "foobar.com", "/foo", datetime.now())
d.response.body = "This is a test!"
d.request.method = "GET"
d.save()

d = DocHTTPRequestResponse(
        protocol="http",
        host="foobar.com",
        port=80
        )
d.add_request_header("User-Agent: foobar")
d.add_request_parameter("url", "id", "123")
d.add_request_parameter("url", "doc", "456")
d.add_response_header("X-Frame-Options: SAMEORIGIN")
d.add_response_cookie("SESSIONID", "foobar1234")
d.add_response_cookie("foo", "bar", "foobar.com", "/foo", datetime.now())
d.request.method = "GET"
d.response.body = "This is a test!"
d.save()

d = DocHTTPRequestResponse(
        protocol="http",
        host="foobar.com",
        port=80
        )
d.add_request_header("User-Agent: foobar")
d.add_request_parameter("body", "action", "add")
d.add_request_parameter("body", "doc", "456")
d.add_request_parameter("body", "content", "Test")
d.add_request_parameter("body", "csrftoken", "trulyrandom")
d.add_response_header("X-Frame-Options: SAMEORIGIN")
d.add_response_cookie("SESSIONID", "foobar1234")
d.add_response_cookie("foo", "bar", "foobar.com", "/foo", datetime.now())
d.request.method = "POST"
d.response.body = "Added!"
d.save()

d = DocHTTPRequestResponse(
        protocol="http",
        host="foobar.com",
        port=80
        )
d.add_request_header("User-Agent: foobar")
d.add_request_parameter("body", "action", "delete")
d.add_request_parameter("body", "doc", "456")
d.add_response_header("X-Frame-Options: SAMEORIGIN")
d.add_response_cookie("SESSIONID", "foobar1234")
d.add_response_cookie("foo", "bar", "foobar.com", "/foo", datetime.now())
d.request.method = "POST"
d.response.body = "Deleted!"
d.save()
