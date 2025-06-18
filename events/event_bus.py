"""
Event Bus for real-time WebSocket notifications
"""

import asyncio
import logging
from typing import Dict, List, Callable, Any
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class Event:
    """Event data structure"""
    type: str
    data: Dict[str, Any]
    timestamp: float
    source: str = "system"


class EventBus:
    """
    Centralized event bus for broadcasting state changes to WebSocket clients
    """
    
    def __init__(self):
        self.listeners: Dict[str, List[Callable]] = defaultdict(list)
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self.running = False
        self.processor_task = None
        logger.info("EventBus initialized")
    
    async def start(self):
        """Start the event processor"""
        if not self.running:
            self.running = True
            self.processor_task = asyncio.create_task(self._process_events())
            logger.info("EventBus started")
    
    async def stop(self):
        """Stop the event processor"""
        self.running = False
        if self.processor_task:
            await self.processor_task
            logger.info("EventBus stopped")
    
    async def _process_events(self):
        """Process events from the queue"""
        while self.running:
            try:
                # Wait for events with timeout to allow checking running status
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                await self._dispatch_event(event)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error processing event: {e}")
    
    async def _dispatch_event(self, event: Event):
        """Dispatch event to all registered listeners"""
        listeners = self.listeners.get(event.type, [])
        
        if not listeners:
            logger.debug(f"No listeners for event type: {event.type}")
            return
        
        logger.debug(f"Dispatching {event.type} to {len(listeners)} listeners")
        
        # Create tasks for all listeners to run concurrently
        tasks = []
        for listener in listeners:
            task = asyncio.create_task(self._call_listener(listener, event))
            tasks.append(task)
        
        # Wait for all listeners to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Log any errors
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Listener {listeners[i].__name__} failed: {result}")
    
    async def _call_listener(self, listener: Callable, event: Event):
        """Call a listener with error handling"""
        try:
            await listener(event)
        except Exception as e:
            logger.error(f"Error in listener {listener.__name__}: {e}")
            raise
    
    def subscribe(self, event_type: str, listener: Callable):
        """Subscribe to an event type"""
        self.listeners[event_type].append(listener)
        logger.info(f"Subscribed {listener.__name__} to {event_type}")
    
    def unsubscribe(self, event_type: str, listener: Callable):
        """Unsubscribe from an event type"""
        if listener in self.listeners[event_type]:
            self.listeners[event_type].remove(listener)
            logger.info(f"Unsubscribed {listener.__name__} from {event_type}")
    
    async def emit(self, event_type: str, data: Dict[str, Any], source: str = "system"):
        """Emit an event"""
        event = Event(
            type=event_type,
            data=data,
            timestamp=datetime.now().timestamp(),
            source=source
        )
        
        await self.event_queue.put(event)
        logger.debug(f"Emitted event: {event_type} from {source}")


# Global event bus instance
event_bus = EventBus()


# Event types
class EventTypes:
    """Standard event types"""
    # Transaction events
    TRANSACTION_PENDING = "transaction_pending"
    TRANSACTION_CONFIRMED = "transaction_confirmed"
    TRANSACTION_FAILED = "transaction_failed"
    
    # Block events
    BLOCK_ADDED = "block_added"
    BLOCK_VALIDATED = "block_validated"
    
    # UTXO events
    UTXO_CREATED = "utxo_created"
    UTXO_SPENT = "utxo_spent"
    
    # Wallet events
    WALLET_BALANCE_CHANGED = "wallet_balance_changed"
    
    # Network events
    PEER_CONNECTED = "peer_connected"
    PEER_DISCONNECTED = "peer_disconnected"
    
    # Bridge events
    BRIDGE_DEPOSIT = "bridge_deposit"
    BRIDGE_WITHDRAWAL = "bridge_withdrawal"