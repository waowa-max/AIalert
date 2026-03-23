from typing import Dict, Optional
from datetime import datetime
from app.core.models import Ticket, TicketStatus, IncidentGroup, Severity

# 工单管理系统 (Mock)
class TicketManager:
    def __init__(self):
        self._tickets: Dict[str, Ticket] = {}
    
    def create_ticket(self, incident: IncidentGroup) -> Ticket:
        # 幂等性：每个聚合实例只对应一个工单
        if incident.ticket_id:
            return self._tickets.get(incident.ticket_id)
        
        ticket_id = f"TKT-{int(datetime.now().timestamp())}"
        ticket = Ticket(
            ticket_id=ticket_id,
            group_id=incident.group_id,
            priority=incident.severity,
            status=TicketStatus.NEW,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        self._tickets[ticket_id] = ticket
        incident.ticket_id = ticket_id
        return ticket
    
    def update_status(self, ticket_id: str, new_status: TicketStatus):
        ticket = self._tickets.get(ticket_id)
        if ticket:
            ticket.status = new_status
            ticket.updated_at = datetime.now()
            return ticket
        return None

# 通知发送器 (Mock IM Card)
class NotificationSender:
    def send_incident_card(self, incident: IncidentGroup, ticket: Ticket):
        # 模拟发送钉钉/飞书卡片
        card_content = {
            "title": f"🚨 {incident.title}",
            "severity": incident.severity,
            "incident_id": incident.group_id,
            "ticket_id": ticket.ticket_id,
            "event_count": incident.event_count,
            "first_seen": incident.first_seen_at.strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": incident.last_seen_at.strftime("%Y-%m-%d %H:%M:%S"),
            "buttons": [
                {"label": "立即认领", "action": f"ACK_TICKET_{ticket.ticket_id}"},
                {"label": "查看详情", "url": f"https://ops.example.com/incident/{incident.group_id}"},
                {"label": "标记误报", "action": f"FALSE_POSITIVE_{incident.group_id}"}
            ]
        }
        
        print(f"--- [SENDING IM CARD] ---")
        print(f"To: Ops_Group_Channel")
        print(f"Content: {card_content}")
        print(f"--------------------------")
        return True
