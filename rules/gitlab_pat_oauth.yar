rule GitLabPatOAuthRule : GitLab
{
    meta:
        name = "GitLab Personal Access Token OAuth style"
        author = "github.com/chrispritchard"
        date = "2022-07-25"
        test_match_1 = "oauth2:ab123mr980pas453201s"

    strings:
        $ = /oauth2\s*(:|=>|=)\s*[a-z0-9_]{20}/ fullword ascii nocase

    condition:
        any of them
}