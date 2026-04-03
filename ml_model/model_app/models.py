from django.db import models
import time


class AlertRecord(models.Model):
    """Persisted IDS alert — written once per alert, never mutated."""
    timestamp    = models.FloatField(default=time.time)
    src_ip       = models.GenericIPAddressField(null=True, blank=True)
    dst_ip       = models.GenericIPAddressField(null=True, blank=True)
    sport        = models.IntegerField(null=True, blank=True)
    dport        = models.IntegerField(null=True, blank=True)
    protocol     = models.CharField(max_length=10, blank=True)
    attack_type  = models.CharField(max_length=64, blank=True)
    severity     = models.CharField(max_length=16, blank=True)
    confidence   = models.FloatField(default=0.0)
    mitre_id     = models.CharField(max_length=32, blank=True)
    mitre_tactic = models.CharField(max_length=64, blank=True)
    abuse_score  = models.IntegerField(default=0)
    incident_id  = models.CharField(max_length=64, blank=True)
    is_simulated = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']
        indexes  = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['src_ip']),
            models.Index(fields=['attack_type']),
        ]

    def to_dict(self):
        return {
            'id':          self.pk,
            'timestamp':   self.timestamp,
            'src_ip':      self.src_ip,
            'dst_ip':      self.dst_ip,
            'sport':       self.sport,
            'dport':       self.dport,
            'protocol':    self.protocol,
            'attack_type': self.attack_type,
            'severity':    self.severity,
            'confidence':  self.confidence,
            'mitre_id':    self.mitre_id,
            'mitre_tactic':self.mitre_tactic,
            'abuse_score': self.abuse_score,
            'incident_id': self.incident_id,
            'is_simulated':self.is_simulated,
        }


class NetworkFlow(models.Model):
    """Classified network flow — one record per completed flow."""
    start_time    = models.FloatField(default=time.time)
    end_time      = models.FloatField(default=time.time)
    src_ip        = models.GenericIPAddressField(null=True, blank=True)
    dst_ip        = models.GenericIPAddressField(null=True, blank=True)
    sport         = models.IntegerField(null=True, blank=True)
    dport         = models.IntegerField(null=True, blank=True)
    protocol      = models.CharField(max_length=10, blank=True)
    bytes_fwd     = models.BigIntegerField(default=0)
    bytes_bwd     = models.BigIntegerField(default=0)
    packets_fwd   = models.IntegerField(default=0)
    packets_bwd   = models.IntegerField(default=0)
    flow_duration = models.FloatField(default=0.0)   # seconds
    attack_type   = models.CharField(max_length=64, blank=True)
    severity      = models.CharField(max_length=16, blank=True)
    confidence    = models.FloatField(default=0.0)
    is_simulated  = models.BooleanField(default=False)

    class Meta:
        ordering = ['-start_time']
        indexes  = [
            models.Index(fields=['start_time']),
            models.Index(fields=['attack_type']),
            models.Index(fields=['severity']),
            models.Index(fields=['src_ip']),
        ]

    def to_dict(self):
        return {
            'id':           self.pk,
            'start_time':   self.start_time,
            'end_time':     self.end_time,
            'src_ip':       self.src_ip,
            'dst_ip':       self.dst_ip,
            'sport':        self.sport,
            'dport':        self.dport,
            'protocol':     self.protocol,
            'bytes_fwd':    self.bytes_fwd,
            'bytes_bwd':    self.bytes_bwd,
            'packets_fwd':  self.packets_fwd,
            'packets_bwd':  self.packets_bwd,
            'flow_duration':self.flow_duration,
            'attack_type':  self.attack_type,
            'severity':     self.severity,
            'confidence':   self.confidence,
            'is_simulated': self.is_simulated,
        }


class BlockedIP(models.Model):
    """System-level firewall-blocked IP entry."""
    ip          = models.GenericIPAddressField(unique=True)
    reason      = models.TextField(blank=True)
    blocked_at  = models.FloatField(default=time.time)
    blocked_by  = models.CharField(max_length=255, blank=True)  # username
    is_active   = models.BooleanField(default=True)
    unblocked_at = models.FloatField(null=True, blank=True)
    unblocked_by = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ['-blocked_at']
        indexes  = [
            models.Index(fields=['ip']),
            models.Index(fields=['is_active']),
        ]

    def to_dict(self):
        return {
            'id':           self.pk,
            'ip':           self.ip,
            'reason':       self.reason,
            'blocked_at':   self.blocked_at,
            'blocked_by':   self.blocked_by,
            'is_active':    self.is_active,
            'unblocked_at': self.unblocked_at,
            'unblocked_by': self.unblocked_by,
        }


class DeviceAlertEmail(models.Model):
    """Maps a hotspot client IP to one or more alert email recipients."""
    ip           = models.CharField(max_length=45, blank=True)   # 192.168.137.x
    mac          = models.CharField(max_length=17, blank=True)   # AA-BB-CC-DD-EE-FF
    label        = models.CharField(max_length=128, blank=True)  # friendly name
    email        = models.EmailField()
    min_severity = models.CharField(max_length=10, default='Medium')  # Low/Medium/High
    enabled      = models.BooleanField(default=True)
    created_at   = models.FloatField(default=time.time)

    class Meta:
        ordering = ['ip', 'email']
        indexes  = [
            models.Index(fields=['ip']),
            models.Index(fields=['mac']),
            models.Index(fields=['enabled']),
        ]

    def to_dict(self):
        return {
            'id':           self.pk,
            'ip':           self.ip,
            'mac':          self.mac,
            'label':        self.label,
            'email':        self.email,
            'min_severity': self.min_severity,
            'enabled':      self.enabled,
            'created_at':   self.created_at,
        }


class PushSubscription(models.Model):
    """Browser Web Push subscription endpoint — one per browser session."""
    endpoint     = models.TextField(unique=True)
    p256dh       = models.TextField()   # client public key
    auth         = models.TextField()   # auth secret
    user_agent   = models.CharField(max_length=255, blank=True)
    created_at   = models.FloatField(default=time.time)
    last_used_at = models.FloatField(default=time.time)

    class Meta:
        ordering = ['-created_at']

    def to_dict(self):
        return {
            'id':       self.pk,
            'endpoint': self.endpoint,
            'p256dh':   self.p256dh,
            'auth':     self.auth,
        }
