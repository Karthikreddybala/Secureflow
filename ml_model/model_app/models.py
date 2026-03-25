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
