Github developer notes
======================

- Accept: application/vnd.github.v3+json needs to be in the header.
- All API access is over HTTPS, and accessed from <https://api.github.com>. All data is sent and received as JSON.
- All timestamps return in ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ (This looks like RFC3339 compatible too).

Github app authenticates via JWT signed by a private key:
ruby example:

```ruby
require 'openssl'
require 'jwt'  # https://rubygems.org/gems/jwt

# Private key contents
private_pem = File.read(YOUR_PATH_TO_PEM)
private_key = OpenSSL::PKey::RSA.new(private_pem)

# Generate the JWT
payload = {
  # issued at time
  iat: Time.now.to_i,
  # JWT expiration time (10 minute maximum)
  exp: Time.now.to_i + (10 * 60),
  # GitHub App's identifier
  iss: YOUR_APP_ID
}

jwt = JWT.encode(payload, private_key, "RS256")
puts jwt
```

After creating the JWT, set it in the Header of the API request:

```curl
curl -i -H "Authorization: Bearer YOUR_JWT" -H "Accept: application/vnd.github.v3+json" https://api.github.com/app
```

To create an installation access token, include the JWT generated above in the Authorization header in the API request:

```curl
curl -i -X POST \
-H "Authorization: Bearer YOUR_JWT" \
-H "Accept: application/vnd.github.machine-man-preview+json" \
https://api.github.com/app/installations/:installation_id/access_tokens
```

Github webhook contains:

- repo meta,
- before, after sha256 hashes.

(Looks like a good idea to associate reports with sha256 hashes.)

HTTP-based Git access by an installation
----------------------------------------

Installations with permissions on contents of a repository, can use their installation access tokens to authenticate for Git access. Use the installation access token as the HTTP password:

git clone https://x-access-token:<token>@github.com/owner/repo.git