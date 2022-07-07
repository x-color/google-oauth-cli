# Google OAuth CLI

It is a tool to be authorized with OAuth 2.0(Authorization Code Flow with Proof Key for Code Exchange) and access Google API.

Read [this blog](https://zenn.dev/x_color/articles/google-oauth-cli) for details.

## Usage

Before using the cli, you must prepare Google OAuth Client settings. See https://developers.google.com/identity/protocols/oauth2/native-app#prerequisites.

Install the cli

```
$ go install github.com/x-color/google-oauth-cli@latest
$ google-oauth-cli
This command has login, logout, email commands. Please use them.
```

Set environment variables

```
$ export CLIENT_ID=<CLIENT ID>
$ export CLIENT_SECRET=<CLIENT SECRET>
```

Authorize the cli with OAuth

```
$ google-oauth-cli login
```

Get your google account's mail address

```
$ google-oauth-cli email
Your email address is <YOUR ADDRESS>
```

Remove a token

```
$ google-oauth-cli logout
```
