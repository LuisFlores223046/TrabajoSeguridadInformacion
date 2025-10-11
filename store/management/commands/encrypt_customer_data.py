# store/management/commands/encrypt_customer_data.py
"""
Comando de Django para cifrar datos de clientes

Uso:
    python manage.py encrypt_customer_data
    python manage.py encrypt_customer_data --verify
    python manage.py encrypt_customer_data --customer-id 1
"""

from django.core.management.base import BaseCommand, CommandError
from store.models import Customer
from store.encryption import encrypt_sensitive_data
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Cifra datos sensibles de clientes usando AES-RSA híbrido'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--customer-id',
            type=int,
            help='ID de un customer específico para cifrar',
        )
        
        parser.add_argument(
            '--verify',
            action='store_true',
            help='Verifica el cifrado de los datos',
        )
        
        parser.add_argument(
            '--force',
            action='store_true',
            help='Fuerza re-cifrado incluso si ya está cifrado',
        )
    
    def handle(self, *args, **options):
        if options['verify']:
            self.verify_encryption()
            return
        
        customer_id = options.get('customer_id')
        force = options.get('force')
        
        if customer_id:
            self.encrypt_single_customer(customer_id, force)
        else:
            self.encrypt_all_customers(force)
    
    def encrypt_single_customer(self, customer_id, force=False):
        """Cifra datos de un customer específico"""
        try:
            customer = Customer.objects.get(id=customer_id)
            self.stdout.write(f"Procesando customer: {customer.user.username}")
            
            if self.encrypt_customer(customer, force):
                self.stdout.write(
                    self.style.SUCCESS(f'✓ Customer {customer.user.username} cifrado exitosamente')
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f'→ Customer {customer.user.username} ya estaba cifrado')
                )
                
        except Customer.DoesNotExist:
            raise CommandError(f'Customer con ID {customer_id} no existe')
        except Exception as e:
            raise CommandError(f'Error cifrando customer: {e}')
    
    def encrypt_all_customers(self, force=False):
        """Cifra datos de todos los customers"""
        customers = Customer.objects.all()
        total = customers.count()
        
        self.stdout.write(f"\nIniciando cifrado de {total} customers...")
        self.stdout.write("=" * 60)
        
        success = 0
        skipped = 0
        errors = 0
        
        for i, customer in enumerate(customers, 1):
            try:
                self.stdout.write(f"[{i}/{total}] Procesando {customer.user.username}...")
                
                if self.encrypt_customer(customer, force):
                    success += 1
                    self.stdout.write(
                        self.style.SUCCESS(f'  ✓ Cifrado exitoso')
                    )
                else:
                    skipped += 1
                    self.stdout.write(
                        self.style.WARNING(f'  → Ya cifrado (use --force para re-cifrar)')
                    )
                    
            except Exception as e:
                errors += 1
                self.stdout.write(
                    self.style.ERROR(f'  ✗ Error: {e}')
                )
        
        # Resumen
        self.stdout.write("\n" + "=" * 60)
        self.stdout.write(self.style.SUCCESS("RESUMEN DE CIFRADO"))
        self.stdout.write("=" * 60)
        self.stdout.write(f"Total de customers: {total}")
        self.stdout.write(self.style.SUCCESS(f"Cifrados exitosamente: {success}"))
        self.stdout.write(self.style.WARNING(f"Omitidos (ya cifrados): {skipped}"))
        if errors > 0:
            self.stdout.write(self.style.ERROR(f"Errores: {errors}"))
        self.stdout.write("=" * 60 + "\n")
    
    def encrypt_customer(self, customer, force=False):
        """
        Cifra datos de un customer
        
        Returns:
            bool: True si se cifró, False si ya estaba cifrado
        """
        updated = False
        
        # Cifrar teléfono
        if customer.phone and (force or not customer.encrypted_phone):
            encrypted_phone = encrypt_sensitive_data(customer.phone)
            customer.encrypted_phone = encrypted_phone['encrypted_data']
            customer.phone_key = encrypted_phone['encrypted_key']
            customer.phone_iv = encrypted_phone['iv']
            updated = True
            logger.info(f"Teléfono cifrado para {customer.user.username}")
        
        # Cifrar dirección
        if customer.address and (force or not customer.encrypted_address):
            encrypted_address = encrypt_sensitive_data(customer.address)
            customer.encrypted_address = encrypted_address['encrypted_data']
            customer.address_key = encrypted_address['encrypted_key']
            customer.address_iv = encrypted_address['iv']
            updated = True
            logger.info(f"Dirección cifrada para {customer.user.username}")
        
        if updated:
            customer.save()
            return True
        
        return False
    
    def verify_encryption(self):
        """Verifica que el cifrado funcione correctamente"""
        customers = Customer.objects.all()
        total = customers.count()
        
        self.stdout.write(f"\nVerificando cifrado de {total} customers...")
        self.stdout.write("=" * 60)
        
        verified = 0
        errors = []
        
        for i, customer in enumerate(customers, 1):
            try:
                self.stdout.write(f"[{i}/{total}] Verificando {customer.user.username}...")
                
                # Intentar descifrar
                phone = customer.phone
                address = customer.address
                
                # Verificar que los datos descifrados coincidan con los campos originales
                status = []
                if customer.encrypted_phone:
                    status.append(f"Teléfono: ✓ ({len(customer.encrypted_phone)} bytes cifrados)")
                if customer.encrypted_address:
                    status.append(f"Dirección: ✓ ({len(customer.encrypted_address)} bytes cifrados)")
                
                if status:
                    self.stdout.write(self.style.SUCCESS(f"  ✓ {', '.join(status)}"))
                    verified += 1
                else:
                    self.stdout.write(self.style.WARNING(f"  → Sin datos cifrados"))
                    
            except Exception as e:
                errors.append({
                    'username': customer.user.username,
                    'error': str(e)
                })
                self.stdout.write(self.style.ERROR(f"  ✗ Error: {e}"))
        
        # Resumen de verificación
        self.stdout.write("\n" + "=" * 60)
        self.stdout.write(self.style.SUCCESS("RESUMEN DE VERIFICACIÓN"))
        self.stdout.write("=" * 60)
        self.stdout.write(f"Total de customers: {total}")
        self.stdout.write(self.style.SUCCESS(f"Verificados correctamente: {verified}"))
        if errors:
            self.stdout.write(self.style.ERROR(f"Errores encontrados: {len(errors)}"))
            for error in errors:
                self.stdout.write(self.style.ERROR(f"  - {error['username']}: {error['error']}"))
        self.stdout.write("=" * 60 + "\n")
