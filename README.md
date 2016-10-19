# TwitterFunctionApp
A simple function app to make posts to twitter - see https://blog.cynexia.com/twitter-bot-as-a-function-app
 
 the app takes a simple JSON as the POST body:
```JSON
{
  "oauth_token": "<your oAuth token>",
  "oauth_token_secret": "<your oAuth token secret>",
  "oauth_consumer_key": "<your consumer key>",
  "oauth_consumer_secret": "<your consumer secret>",
  "tweet": "<the message to send>"
}
```
You can obtain the oAuth token and oAuth secret by following the instructions on the Twitter Developer site at https://dev.twitter.com/oauth/overview/application-owner-access-tokens.
