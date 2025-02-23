import json
import hmac
import hashlib
import logging
import re

from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.urls import path
from django_scopes import scope
from django.contrib import messages
from django.utils.translation import gettext_lazy as _

from pretix.base.models import Organizer, OrderPayment

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet
from rest_framework import permissions, mixins

logger = logging.getLogger(__name__)


def verify_webhook(request, expected_token):
    """Verify Daimo Pay webhook signature"""
    auth_token = request.headers.get('Authorization')
    if not auth_token:
        return False
        
    # Remove Bearer prefix if present
    if auth_token.startswith('Bearer: '):
        auth_token = auth_token[8:]

    print(f"WEBHOOK: tok {auth_token} exp {expected_token}")

    return auth_token == expected_token


@csrf_exempt
@require_POST
def daimo_webhook(request, *args, **kwargs):
    """Handle Daimo Pay webhook events"""
    try:
        # Parse webhook payload
        payload = json.loads(request.body)
        event_type = payload.get('type')
        payment_id = payload.get('paymentId')
        print(f"WEBHOOK RECEIVED: {event_type} {payment_id}")
        if not event_type or not payment_id:
            return HttpResponseBadRequest("Missing event type or payment ID")
        if event_type != 'payment_completed':
            return HttpResponse(status=200)

        # Find payment and its organizer
        # Get all organizers since we can't scope the initial query
        organizers = Organizer.objects.all()
        payment = None

        # Try each organizer scope until we find the payment
        for organizer in organizers:
            with scope(organizer=organizer):
                try:
                    # Use proper JSON field lookup
                    payment = OrderPayment.objects.select_related(
                        'order__event__organizer'
                    ).filter(
                        info__icontains=payment_id
                    ).get()
                    break
                except OrderPayment.DoesNotExist:
                    continue

        if not payment:
            return HttpResponseBadRequest("Payment not found")

        print(f"WEBHOOK: found payment {payment.id}")

        # Continue with the correct scope
        with scope(organizer=payment.order.event.organizer):
            # Verify webhook signature within the correct scope
            if not verify_webhook(request, payment.payment_provider.settings.DAIMO_PAY_WEBHOOK_TOKEN):
                print(f"WEBHOOK: invalid token")
                return HttpResponseBadRequest("Invalid token")
                
            # Handle payment completion
            payment.payment_provider.confirm_payment_by_id(payment_id, payment)
                
            return HttpResponse(status=200)
            
    except (json.JSONDecodeError, KeyError) as e:
        return HttpResponseBadRequest(f"Invalid webhook payload: {str(e)}")
    except Exception as e:
        logger.exception("Error processing webhook")
        return HttpResponseBadRequest(f"Error processing webhook: {str(e)}")

# URL configuration
webhook_patterns = [
    path('webhook/', daimo_webhook, name='webhook'),
]
# No views needed beyond webhook handler
