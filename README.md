# get idtoken (good for 6 hours)
curl -X GET "https://expander.expanse.co/api/v1/IdToken/" -H "Authorization: Bearer <BearerTokenFromPDF>" -H "Accept: application/json"
 
# get exposures for a single IP
curl -X GET "https://expander.expanse.co/api/v2/exposures/ip-ports?limit=100&offset=0&inet=<ipaddress>" -H "accept: application/json" -H "Authorization: JWT <idtoken>"

API Docs for other methods: https://expander.expanse.co/api/v1/docs/