def valid_lesson(topic, body):
    return bool(topic and body and len(body) > 5)
def valid_finding(title, class_id):
    return bool(title and class_id)
