use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
run_tests();

__DATA__
=== TEST 1: auth_file should be return 401
--- user_files
>>> test
LMyDuTCwch0tJDmKPpWm1A==

--- config
location = /index.html {
    auth_file html/test;
    root html;
    index html;
}

--- request
GET /index.html

--- error_code: 401

=== TEST 2: auth_file should return ok
--- user_files
>>> test
LMyDuTCwch0tJDmKPpWm1A==

--- config
location = /index.html {
    auth_file html/test;
    root html;
    index html;
}

--- more_headers
Authorization: LMyDuTCwch0tJDmKPpWm1A==

--- request
GET /index.html

--- error_code: 200

