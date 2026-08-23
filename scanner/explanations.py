FRIENDLY_RULES = {

    "SQL Injection": {
        "title": "SQL Injection",

        "description": (
            "Your application may be using information provided by a user "
            "directly inside a database query."
        ),

        "impact": (
            "An attacker may be able to access, change or delete information "
            "stored in your database."
        ),

        "remediation": (
            "Use parameterised queries or prepared statements instead of "
            "building database queries directly from user input."
        )
    },

    "Cross-Site Scripting (XSS)": {
        "title": "Cross-Site Scripting (XSS)",

        "description": (
            "Your application may display user-provided content without "
            "safely processing it first."
        ),

        "impact": (
            "An attacker may be able to run malicious code inside another "
            "user's browser."
        ),

        "remediation": (
            "Avoid inserting user input directly into HTML. Use your web "
            "framework's automatic escaping and safe templating features."
        )
    },

    "Command Injection": {
        "title": "Command Injection",

        "description": (
            "Your application may allow user-provided information to influence "
            "commands executed by the operating system."
        ),

        "impact": (
            "An attacker may be able to execute unintended commands on "
            "the server."
        ),

        "remediation": (
            "Avoid passing user input directly to system commands and use "
            "safe APIs that do not invoke a shell where possible."
        )
    },

    "Other Security Issue": {
        "title": "Security Issue",

        "description": (
            "The security scanner detected potentially unsafe code."
        ),

        "impact": (
            "The impact of this issue depends on how the affected code is used."
        ),

        "remediation": (
            "Review the technical details below before deploying the application."
        )
    }
}


def get_friendly_info(category):

    return FRIENDLY_RULES.get(
        category,
        FRIENDLY_RULES["Other Security Issue"]
    )