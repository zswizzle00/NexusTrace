import requests
from bs4 import BeautifulSoup
import re
from ..utils.cache import timed_lru_cache
from ..utils.constants import TIMEOUT_MEDIUM

@timed_lru_cache(seconds=3600)
def get_event_info(event_id):
    """Scrape Windows Event ID details from the Ultimate Windows Security encyclopedia."""
    try:
        url = f"https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={event_id}"
        response = requests.get(url, timeout=TIMEOUT_MEDIUM)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        event_info = {
            'event_id': event_id,
            'title': '',
            'summary': '',
            'details_table': [],
            'fields': '',
        }

        title_span = soup.find('span', id='ctl00_ctl00_ctl00_ctl00_Content_Content_Content_Content_litEventTitle')
        if title_span:
            event_info['title'] = title_span.get_text(strip=True)

        summary_p = soup.find('p', class_='hey')
        if summary_p:
            event_info['summary'] = summary_p.get_text(strip=True)
            next_p = summary_p.find_next_sibling('p')
            if next_p:
                event_info['summary'] += '\n' + next_p.get_text(strip=True)

        table = soup.find('table', attrs={'border': '1'})
        if table:
            rows = []
            for tr in table.find_all('tr'):
                cols = [td.get_text(strip=True) for td in tr.find_all('td')]
                if cols:
                    rows.append(cols)
            event_info['details_table'] = rows

        fields_span = soup.find('span', id='ctl00_ctl00_ctl00_ctl00_Content_Content_Content_Content_FieldsDiv')
        if fields_span:
            event_info['fields'] = fields_span.get_text('\n', strip=True)

        return event_info

    except requests.RequestException as e:
        return {
            'event_id': event_id,
            'title': '',
            'summary': f'Error fetching event information: {str(e)}',
            'details_table': [],
            'fields': '',
        } 