from flask import g
from pubsub import pub


def send_message(topic_name: str = None, **kwargs):
    pub.sendMessage(topicName=topic_name, **kwargs)


def get_event_object(topic_name: str = None):
    return getattr(g, topic_name, None)
