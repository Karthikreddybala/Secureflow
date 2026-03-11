from django.core.management.base import BaseCommand
import asyncio
import logging
from model_app.views import start_parallel_processors, get_processing_stats

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Start the parallel background processors for ML model predictions'

    def add_arguments(self, parser):
        parser.add_argument(
            '--workers',
            type=int,
            default=3,
            help='Number of parallel workers (default: 3)'
        )

    def handle(self, *args, **options):
        num_workers = options['workers']
        self.stdout.write(
            self.style.SUCCESS(f'Starting {num_workers} parallel background processors...')
        )
        logger.info(f"Starting {num_workers} parallel background processors")
        
        try:
            # Run the parallel processors
            start_parallel_processors(num_workers)
        except KeyboardInterrupt:
            self.stdout.write(
                self.style.WARNING('Background processors stopped by user')
            )
            logger.info("Background processors stopped by user")
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Background processors failed: {e}')
            )
            logger.error(f"Background processors failed: {e}")

    def get_stats(self):
        """Display current processing statistics"""
        stats = get_processing_stats()
        self.stdout.write("\n" + "="*50)
        self.stdout.write("PROCESSING STATISTICS")
        self.stdout.write("="*50)
        self.stdout.write(f"Flows processed: {stats['flows_processed']}")
        self.stdout.write(f"Packets processed: {stats['packets_processed']}")
        self.stdout.write(f"Avg packets per flow: {stats['avg_packets_per_flow']:.2f}")
        self.stdout.write(f"Queue depth: {stats['queue_depth']}")
        self.stdout.write(f"Flows in memory: {stats['flows_in_memory']}")
        self.stdout.write(f"Processing rate (flows/sec): {stats['processing_rate_flows_per_sec']:.2f}")
        self.stdout.write(f"Processing rate (packets/sec): {stats['processing_rate_packets_per_sec']:.2f}")
        self.stdout.write(f"Uptime: {stats['uptime_seconds']:.1f} seconds")
        self.stdout.write("="*50 + "\n")
