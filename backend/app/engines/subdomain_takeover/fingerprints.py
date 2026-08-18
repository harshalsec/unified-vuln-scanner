from typing import Dict, List

VULNERABLE_FINGERPRINTS: Dict[str, List[str]] = {
    "GitHub Pages": [
        "there isn't a github pages site here",
        "for root urls (like http://example.com/) you must provide an index.html file",
        "the site configured at this address does not contain the requested file",
    ],
    "Heroku": [
        "no such app",
        "no-such-app",
        "there's nothing here, yet.",
        "heroku | no such app",
    ],
    "AWS S3": [
        "nosuchbucket",
        "the specified bucket does not exist",
        "nosuchkey",
        "the specified key does not exist",
    ],
    "Shopify": [
        "sorry, this shop is currently unavailable",
        "only one step left",
        "this shop is unavailable",
    ],
    "Tumblr": [
        "there's nothing here.",
        "whatever you were looking for doesn't currently exist at this address",
    ],
    "Ghost": [
        "the thing you were looking for is no longer here",
        "domain not configured",
        "ghost domain error",
    ],
    "Pantheon": [
        "404 error unknown site",
        "the gods are wise",
    ],
    "Cargo Collective": [
        "404 not found",
        "cargo collective",
    ],
    "Ngrok": [
        "ngrok.io not found",
        "tunnel not found",
        "the endpoint is offline",
    ],
    "Bitbucket": [
        "repository not found",
        "the page you're looking for doesn't exist",
    ],
    "Surge.sh": [
        "project not found",
        "repository not found",
    ],
    "Azure": [
        "404 web site not found",
        "the resource you are looking for has been removed",
        "error 404 - web app not found",
    ],
    "Netlify": [
        "not found - request id",
        "netlify",
        "page not found",
    ],
    "WordPress.com": [
        "do you want to register",
        "doesn't exist",
    ],
    "Help Scout": [
        "no settings were found for this company",
        "we could not find what you're looking for",
    ],
    "Readme.io": [
        "project doesnt exist",
        "this project does not exist",
    ],
    "JetBrains": [
        "is not a registered incloud youtrack",
    ],
    "SmartJobBoard": [
        "this job board website is either expired or its domain has been changed",
    ],
}