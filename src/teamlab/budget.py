"""Conservative pre-request spend reservations at the HTTP boundary.

Prices are operator-supplied, not guessed. Reservations are never refunded and
assume the configured prices cover the selected provider/model. This bounds the
configured estimate, not a provider invoice or future price changes.
"""
import json
import threading
from decimal import Decimal, ROUND_CEILING

from .security import SecurityError


class SpendBudget:
    def __init__(self, usd, input_usd_per_million, output_usd_per_million, max_requests=100):
        self.limit = Decimal(str(usd))
        self.input_rate = Decimal(str(input_usd_per_million))
        self.output_rate = Decimal(str(output_usd_per_million))
        if not all(v.is_finite() and v > 0 for v in (self.limit,self.input_rate,self.output_rate)) or not 1<=max_requests<=100000:
            raise ValueError('positive finite spend limit/rates and 1..100000 request limit required')
        self.max_requests, self.calls, self.reserved, self.lock = max_requests, 0, Decimal(0), threading.Lock()

    def reserve_request(self, request):
        if request.method!='POST' or not request.url.path.endswith('/responses'):
            raise SecurityError('budgeted client only permits Responses inference requests')
        body=request.content
        if len(body)>512_000:
            raise SecurityError('inference input byte quota exceeded')
        data=json.loads(body)
        maximum=data.get('max_output_tokens')
        if data.get('model')!='gpt-6-luna' or type(maximum) is not int or not 1<=maximum<=4096:
            raise SecurityError('explicit bounded Luna response required for spend reservation')
        # Text-only JSON payload bytes overestimate text tokens; reserve extra
        # framing allowance as well. No images/audio or arbitrary provider tools.
        if data.get('tools') and any(t.get('type')!='function' for t in data['tools']):
            raise SecurityError('only fixed function tools supported by budgeted inference')
        encoded=json.dumps(data.get('input',[]))
        if any(marker in encoded for marker in ('"input_image"','"input_audio"','"image_url"','"file_id"')):
            raise SecurityError('only text inputs supported by spend reservations')
        reserve=(Decimal(len(body)+4096)*self.input_rate+Decimal(maximum)*self.output_rate)/Decimal(1_000_000)
        reserve=reserve.quantize(Decimal('.000001'),rounding=ROUND_CEILING)
        with self.lock:
            if self.calls>=self.max_requests or self.reserved+reserve>self.limit:
                raise SecurityError('experiment request/spend reservation budget exhausted')
            self.calls+=1;self.reserved+=reserve

    def client(self):
        import httpx
        return httpx.Client(timeout=45,event_hooks={'request':[self.reserve_request]})

    def async_client(self):
        import httpx
        async def reserve(request):
            self.reserve_request(request)
        return httpx.AsyncClient(timeout=45,event_hooks={'request':[reserve]})

    def report(self):
        return {'requests_reserved':self.calls,'reserved_usd':str(self.reserved),'limit_usd':str(self.limit),
            'input_usd_per_million':str(self.input_rate),'output_usd_per_million':str(self.output_rate),
            'semantics':'Conservative text-request reservations at operator-supplied rates; not measured invoice cost.'}
