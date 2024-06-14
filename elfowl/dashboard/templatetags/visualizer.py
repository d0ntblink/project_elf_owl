import re
from django import template
from django.utils.safestring import mark_safe
from decouple import config

register = template.Library()

@register.filter(name='auto_hyperlink')
def auto_hyperlink(text):
    url_pattern = re.compile(r'(https?://\S+)')
    
    def replace_and_linkify(match):
        url = match.group(0)
        if url.startswith("http://nginx/"):
            url = url.replace("http://nginx/", f"{config('VULNERABLECODE_URL')}/")
        return f'<a href="{url}" target="_blank">{url}</a>'
    
    if isinstance(text, list):
        return [mark_safe(url_pattern.sub(replace_and_linkify, str(item))) for item in text]
    elif isinstance(text, str):
        return mark_safe(url_pattern.sub(replace_and_linkify, text))
    else:
        return text

@register.filter(name='hyperlinkify')
def hyperlinkify(data):
    if not isinstance(data, list):
        return data

    def replace_urls(match):
        url = match.group(0)
        return f'<a href="{url}" target="_blank">{url}</a>'

    hyperlinked_data = []
    for item in data:
        hyperlinked_item = re.sub(r'https?://\S+', replace_urls, item)
        hyperlinked_data.append(mark_safe(hyperlinked_item))

    return hyperlinked_data

@register.filter(name='cwe_hyperlink')
def cwe_hyperlink(text):
    cwe_pattern = re.compile(r'CWE-(\d+)')
    return mark_safe(cwe_pattern.sub(r'<a href="https://cwe.mitre.org/data/definitions/\1.html" target="_blank">CWE-\1</a>', text))
