import requests
from bs4 import BeautifulSoup
import re

def get_event_info(event_id):
    """
    Fetch information about a Windows Event ID from the Ultimate Windows Security website.
    
    Args:
        event_id (str): The Windows Event ID to look up
        
    Returns:
        dict: A dictionary containing the event information
    """
    try:
        url = f"https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={event_id}"
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        event_info = {
            'event_id': event_id,
            'title': '',
            'summary': '',
            'details_table': [],
            'fields': '',
        }

        # Extract event title
        title_span = soup.find('span', id='ctl00_ctl00_ctl00_ctl00_Content_Content_Content_Content_litEventTitle')
        if title_span:
            event_info['title'] = title_span.get_text(strip=True)

        # Extract summary/description (first <p class="hey"> and next <p>)
        summary_p = soup.find('p', class_='hey')
        if summary_p:
            event_info['summary'] = summary_p.get_text(strip=True)
            # Optionally, add the next <p> for more context
            next_p = summary_p.find_next_sibling('p')
            if next_p:
                event_info['summary'] += '\n' + next_p.get_text(strip=True)

        # Extract details from the first table in the right content area
        table = soup.find('table', attrs={'border': '1'})
        if table:
            rows = []
            for tr in table.find_all('tr'):
                cols = [td.get_text(strip=True) for td in tr.find_all('td')]
                if cols:
                    rows.append(cols)
            event_info['details_table'] = rows

        # Extract the fields section (Field level details)
        fields_span = soup.find('span', id='ctl00_ctl00_ctl00_ctl00_Content_Content_Content_Content_FieldsDiv')
        if fields_span:
            # Get all text under this span, preserving some structure
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