import json


def is_trusted_publisher(publisher):

    with open(
        "signature/trusted_publishers.json",
        "r",
        encoding="utf-8"
    ) as file:

        trusted = json.load(file)

    publisher = publisher.lower()

    for company in trusted:

        if company.lower() in publisher:
            return True

    return False