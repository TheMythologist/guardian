import questionary

CIDR_MASKS = [
    0,
    2147483648,
    3221225472,
    3758096384,
    4026531840,
    4160749568,
    4227858432,
    4261412864,
    4278190080,
    4286578688,
    4290772992,
    4292870144,
    4293918720,
    4294443008,
    4294705152,
    4294836224,
    4294901760,
    4294934528,
    4294950912,
    4294959104,
    4294963200,
    4294965248,
    4294966272,
    4294966784,
    4294967040,
    4294967168,
    4294967232,
    4294967264,
    4294967280,
    4294967288,
    4294967292,
    4294967294,
    4294967295,
]

DISCORD_URL = "https://discord.gg/6FzKCh4j4v"
UI_STYLE = questionary.Style(
    [
        ("qmark", "fg:#00FFFF bold"),  # token in front of the question
        ("question", "bold"),  # question text
        ("answer", "fg:#00FFFF bold"),  # submitted answer text behind the question
        ("pointer", "fg:#00FFFF bold"),  # pointer used in select and checkbox prompts
        ("selected", "fg:#FFFFFF bold"),  # style for a selected item of a checkbox
        ("separator", "fg:#00FFFF"),  # separator in lists
        ("instruction", ""),  # user instructions for select, rawselect, checkbox
    ]
)
