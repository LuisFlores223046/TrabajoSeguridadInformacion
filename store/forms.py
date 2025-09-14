# store/forms.py
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from .models import Product, Category, Customer, Order, OrderItem
from .utils.validators import InputValidator, PasswordValidator
import logging

logger = logging.getLogger(__name__)

class SecureFormMixin:
    """
    Mixin para añadir validaciones de seguridad a los formularios
    """
    
    def clean(self):
        """
        Validación adicional de seguridad para todos los campos
        """
        cleaned_data = super().clean()
        
        # Validar todos los campos de texto
        for field_name, value in cleaned_data.items():
            if isinstance(value, str) and value:
                try:
                    # Aplicar validación básica de texto
                    if field_name in ['name', 'username']:
                        cleaned_data[field_name] = InputValidator.validate_product_name(value)
                    elif field_name == 'email':
                        cleaned_data[field_name] = InputValidator.validate_email(value)
                    elif field_name == 'phone':
                        cleaned_data[field_name] = InputValidator.validate_phone(value)
                    elif field_name in ['address', 'shipping_address', 'description']:
                        cleaned_data[field_name] = InputValidator.validate_address(value)
                    else:
                        cleaned_data[field_name] = InputValidator.validate_text_input(value, field_name)
                except ValidationError as e:
                    self.add_error(field_name, e)
        
        return cleaned_data

class CategoryForm(SecureFormMixin, forms.ModelForm):
    """Formulario seguro para crear y editar categorías"""
    
    class Meta:
        model = Category
        fields = ['name', 'description']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'maxlength': '200',
                'pattern': '[a-zA-Z0-9\\s\\-\\.&(),]+',
                'title': 'Only letters, numbers, spaces, and basic punctuation allowed'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control', 
                'rows': 3,
                'maxlength': '500'
            }),
        }
    
    def clean_name(self):
        """Validación específica para nombre de categoría"""
        name = self.cleaned_data.get('name')
        if name:
            name = InputValidator.validate_product_name(name)
            
            # Verificar unicidad
            if Category.objects.filter(name__iexact=name).exclude(pk=self.instance.pk).exists():
                raise ValidationError("A category with this name already exists.")
        
        return name

class ProductForm(SecureFormMixin, forms.ModelForm):
    """Formulario seguro para crear y editar productos"""
    
    class Meta:
        model = Product
        fields = ['name', 'category', 'description', 'price', 'stock', 'image', 
                 'roast_level', 'origin', 'format', 'weight', 'is_available']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'maxlength': '200',
                'pattern': '[a-zA-Z0-9\\s\\-\\.&(),]+',
                'required': True
            }),
            'category': forms.Select(attrs={'class': 'form-select', 'required': True}),
            'description': forms.Textarea(attrs={
                'class': 'form-control', 
                'rows': 3,
                'maxlength': '1000',
                'required': True
            }),
            'price': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': '0',
                'max': '9999.99',
                'step': '0.01',
                'required': True
            }),
            'stock': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': '0',
                'max': '10000',
                'required': True
            }),
            'roast_level': forms.Select(attrs={'class': 'form-select', 'required': True}),
            'origin': forms.TextInput(attrs={
                'class': 'form-control',
                'maxlength': '100',
                'pattern': '[a-zA-Z\\s\\-]+',
                'required': True
            }),
            'format': forms.Select(attrs={'class': 'form-select', 'required': True}),
            'weight': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': '1',
                'max': '5000',
                'required': True
            }),
            'is_available': forms.CheckboxInput(attrs={'class': 'form-check-input'})
        }
    
    def clean_price(self):
        """Validación específica para precio"""
        price = self.cleaned_data.get('price')
        if price is not None:
            return InputValidator.validate_price(price)
        return price
    
    def clean_stock(self):
        """Validación específica para stock"""
        stock = self.cleaned_data.get('stock')
        if stock is not None:
            return InputValidator.validate_quantity(stock)
        return stock
    
    def clean_weight(self):
        """Validación específica para peso"""
        weight = self.cleaned_data.get('weight')
        if weight is not None:
            try:
                weight = int(weight)
                if weight < 1 or weight > 5000:
                    raise ValidationError("Weight must be between 1 and 5000 grams")
                return weight
            except (ValueError, TypeError):
                raise ValidationError("Invalid weight format")
        return weight

class SecureLoginForm(AuthenticationForm):
    """Formulario de login con protecciones adicionales"""
    
    username = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-control', 
            'placeholder': 'Username',
            'maxlength': '150',
            'pattern': '[a-zA-Z0-9@.+\\-_]+',
            'autocomplete': 'username'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control', 
            'placeholder': 'Password',
            'autocomplete': 'current-password'
        })
    )
    
    def clean_username(self):
        """Validación de username"""
        username = self.cleaned_data.get('username')
        if username:
            # Validación básica de seguridad
            username = InputValidator.validate_text_input(username, "username", 150)
            
            # Verificar formato de username
            import re
            if not re.match(r'^[a-zA-Z0-9@.+\-_]+$', username):
                raise ValidationError("Username contains invalid characters")
        
        return username
    
    def clean(self):
        """Validación adicional del formulario"""
        cleaned_data = super().clean()
        
        # Log intento de login para auditoría
        username = cleaned_data.get('username')
        if username:
            logger.info(f"Login attempt for username: {username}")
        
        return cleaned_data

class SecureRegistrationForm(SecureFormMixin, UserCreationForm):
    """Formulario de registro con validaciones de seguridad"""
    
    first_name = forms.CharField(
        max_length=30, 
        required=True, 
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'maxlength': '30',
            'pattern': '[a-zA-Z\\s\\-]+',
            'title': 'Only letters, spaces, and hyphens allowed'
        })
    )
    last_name = forms.CharField(
        max_length=30, 
        required=True, 
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'maxlength': '30',
            'pattern': '[a-zA-Z\\s\\-]+',
            'title': 'Only letters, spaces, and hyphens allowed'
        })
    )
    email = forms.EmailField(
        max_length=254, 
        required=True, 
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'maxlength': '254'
        })
    )
    
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2')
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({
            'class': 'form-control',
            'maxlength': '150',
            'pattern': '[a-zA-Z0-9@.+\\-_]+',
            'title': 'Letters, numbers, and @/./+/-/_ only'
        })
        self.fields['password1'].widget.attrs.update({'class': 'form-control'})
        self.fields['password2'].widget.attrs.update({'class': 'form-control'})
    
    def clean_email(self):
        """Validación de email"""
        email = self.cleaned_data.get('email')
        if email:
            email = InputValidator.validate_email(email)
            
            # Verificar unicidad
            if User.objects.filter(email__iexact=email).exists():
                raise ValidationError("A user with this email already exists.")
        
        return email
    
    def clean_first_name(self):
        """Validación de nombre"""
        first_name = self.cleaned_data.get('first_name')
        if first_name:
            # Validar solo letras, espacios y guiones
            import re
            if not re.match(r'^[a-zA-Z\s\-]+$', first_name):
                raise ValidationError("First name can only contain letters, spaces, and hyphens")
            first_name = InputValidator.validate_text_input(first_name, "first name", 30)
        return first_name
    
    def clean_last_name(self):
        """Validación de apellido"""
        last_name = self.cleaned_data.get('last_name')
        if last_name:
            # Validar solo letras, espacios y guiones
            import re
            if not re.match(r'^[a-zA-Z\s\-]+$', last_name):
                raise ValidationError("Last name can only contain letters, spaces, and hyphens")
            last_name = InputValidator.validate_text_input(last_name, "last name", 30)
        return last_name
    
    def clean_password1(self):
        """Validación de contraseña"""
        password1 = self.cleaned_data.get('password1')
        if password1:
            try:
                PasswordValidator.validate_password_strength(password1)
            except ValidationError as e:
                raise ValidationError(e.messages)
        return password1

class SecureOrderForm(SecureFormMixin, forms.ModelForm):
    """Formulario seguro para actualizar órdenes"""
    
    class Meta:
        model = Order
        fields = ['status', 'shipping_address']
        widgets = {
            'status': forms.Select(attrs={'class': 'form-select'}),
            'shipping_address': forms.Textarea(attrs={
                'class': 'form-control', 
                'rows': 3,
                'maxlength': '500'
            }),
        }

class SecureOrderItemForm(SecureFormMixin, forms.ModelForm):
    """Formulario seguro para añadir/editar ítems de una orden"""
    
    class Meta:
        model = OrderItem
        fields = ['product', 'quantity']
        widgets = {
            'product': forms.Select(attrs={'class': 'form-select'}),
            'quantity': forms.NumberInput(attrs={
                'class': 'form-control', 
                'min': 1,
                'max': 1000
            }),
        }
    
    def clean_quantity(self):
        """Validación de cantidad"""
        quantity = self.cleaned_data.get('quantity')
        if quantity is not None:
            return InputValidator.validate_quantity(quantity)
        return quantity

class SecureSearchForm(forms.Form):
    """Formulario seguro para búsquedas"""
    
    query = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Search products...',
            'maxlength': '100'
        })
    )
    
    def clean_query(self):
        """Validación de consulta de búsqueda"""
        query = self.cleaned_data.get('query')
        if query:
            query = InputValidator.validate_search_query(query)
        return query

class SecureContactForm(SecureFormMixin, forms.Form):
    """Formulario seguro para contacto"""
    
    name = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'maxlength': '100',
            'pattern': '[a-zA-Z\\s\\-]+',
            'required': True
        })
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'maxlength': '254',
            'required': True
        })
    )
    subject = forms.CharField(
        max_length=200,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'maxlength': '200',
            'required': True
        })
    )
    message = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 5,
            'maxlength': '1000',
            'required': True
        })
    )
    
    def clean_name(self):
        """Validación de nombre"""
        name = self.cleaned_data.get('name')
        if name:
            import re
            if not re.match(r'^[a-zA-Z\s\-]+$', name):
                raise ValidationError("Name can only contain letters, spaces, and hyphens")
            name = InputValidator.validate_text_input(name, "name", 100)
        return name