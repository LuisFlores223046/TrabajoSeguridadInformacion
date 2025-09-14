from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from .models import Product, Category, Customer, Order, OrderItem
from .validators import SecureInputValidator
import html
import re

class SecureCharField(forms.CharField):
    """Campo de texto seguro que previene XSS"""
    
    def clean(self, value):
        value = super().clean(value)
        if value:
            # Escapar HTML para prevenir XSS
            value = html.escape(value.strip())
            
            # Validar caracteres permitidos (solo letras, números, espacios, guiones, apostrofes)
            if not re.match(r'^[a-zA-Z0-9\s\-\'\.]+$', value):
                raise ValidationError("Only letters, numbers, spaces, hyphens, periods and apostrophes are allowed.")
            
            # Verificar longitud mínima
            if len(value.strip()) < 2:
                raise ValidationError("This field must be at least 2 characters long.")
        
        return value

class SecureEmailField(forms.EmailField):
    """Campo de email seguro"""
    
    def clean(self, value):
        value = super().clean(value)
        if value:
            value = html.escape(value.strip().lower())
            
            # Validación adicional de email
            if len(value) > 254:
                raise ValidationError("Email address is too long.")
        
        return value

class SecureTextareaField(forms.CharField):
    """Campo de textarea seguro"""
    
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('widget', forms.Textarea)
        super().__init__(*args, **kwargs)
    
    def clean(self, value):
        value = super().clean(value)
        if value:
            # Escapar HTML
            value = html.escape(value.strip())
            
            # Remover scripts y tags peligrosos
            dangerous_patterns = [
                r'<script[^>]*>.*?</script>',
                r'<iframe[^>]*>.*?</iframe>',
                r'javascript:',
                r'on\w+\s*=',
                r'<object[^>]*>.*?</object>',
                r'<embed[^>]*>.*?</embed>'
            ]
            
            for pattern in dangerous_patterns:
                value = re.sub(pattern, '', value, flags=re.IGNORECASE | re.DOTALL)
        
        return value

class CategoryForm(forms.ModelForm):
    """Formulario seguro para crear y editar categorías"""
    
    name = SecureCharField(
        max_length=200,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Category name'})
    )
    description = SecureTextareaField(
        max_length=1000,
        required=False,
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Category description'})
    )
    
    class Meta:
        model = Category
        fields = ['name', 'description']
    
    def clean_name(self):
        name = self.cleaned_data.get('name')
        if name:
            # Verificar unicidad considerando espacios
            existing = Category.objects.filter(name__iexact=name.strip())
            if self.instance.pk:
                existing = existing.exclude(pk=self.instance.pk)
            
            if existing.exists():
                raise ValidationError("A category with this name already exists.")
        
        return name

class ProductForm(forms.ModelForm):
    """Formulario seguro para crear y editar productos"""
    
    name = SecureCharField(
        max_length=200,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Product name'})
    )
    description = SecureTextareaField(
        max_length=1000,
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Product description'})
    )
    origin = SecureCharField(
        max_length=100,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Country or region of origin'})
    )
    
    class Meta:
        model = Product
        fields = ['name', 'category', 'description', 'price', 'stock', 'image', 
                 'roast_level', 'origin', 'format', 'weight', 'is_available']
        widgets = {
            'category': forms.Select(attrs={'class': 'form-select'}),
            'price': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'min': '0.01'}),
            'stock': forms.NumberInput(attrs={'class': 'form-control', 'min': '0'}),
            'roast_level': forms.Select(attrs={'class': 'form-select'}),
            'format': forms.Select(attrs={'class': 'form-select'}),
            'weight': forms.NumberInput(attrs={'class': 'form-control', 'min': '1'}),
            'is_available': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'image': forms.FileInput(attrs={'class': 'form-control', 'accept': 'image/*'})
        }
    
    def clean_price(self):
        price = self.cleaned_data.get('price')
        if price is not None:
            if price <= 0:
                raise ValidationError("Price must be greater than 0.")
            if price > 999999.99:
                raise ValidationError("Price cannot exceed $999,999.99.")
        return price
    
    def clean_stock(self):
        stock = self.cleaned_data.get('stock')
        if stock is not None:
            if stock < 0:
                raise ValidationError("Stock cannot be negative.")
            if stock > 999999:
                raise ValidationError("Stock cannot exceed 999,999 units.")
        return stock
    
    def clean_weight(self):
        weight = self.cleaned_data.get('weight')
        if weight is not None:
            if weight <= 0:
                raise ValidationError("Weight must be greater than 0.")
            if weight > 99999:
                raise ValidationError("Weight cannot exceed 99,999 grams.")
        return weight
    
    def clean_image(self):
        image = self.cleaned_data.get('image')
        if image:
            # Verificar tamaño del archivo
            if image.size > 5 * 1024 * 1024:  # 5MB
                raise ValidationError("Image file size cannot exceed 5MB.")
            
            # Verificar tipo de archivo por extensión
            allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp']
            if not any(image.name.lower().endswith(ext) for ext in allowed_extensions):
                raise ValidationError("Only JPEG, PNG, GIF, and WebP images are allowed.")
        
        return image

class LoginForm(AuthenticationForm):
    """Formulario de login seguro con validaciones adicionales"""
    
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control', 
            'placeholder': 'Username',
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
        username = self.cleaned_data.get('username')
        if username:
            # Sanitizar entrada
            username = html.escape(username.strip())
            
            # Validar caracteres permitidos para username
            if not re.match(r'^[a-zA-Z0-9_@\.\+\-]+$', username):
                raise ValidationError("Username contains invalid characters.")
            
            if len(username) > 150:
                raise ValidationError("Username is too long.")
        
        return username

class RegistrationForm(UserCreationForm):
    """Formulario de registro seguro con campos adicionales"""
    
    first_name = SecureCharField(
        max_length=30, 
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control', 
            'placeholder': 'First name',
            'autocomplete': 'given-name'
        })
    )
    last_name = SecureCharField(
        max_length=30, 
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control', 
            'placeholder': 'Last name',
            'autocomplete': 'family-name'
        })
    )
    email = SecureEmailField(
        max_length=254, 
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control', 
            'placeholder': 'Email address',
            'autocomplete': 'email'
        })
    )
    
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2')
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Username',
            'autocomplete': 'username'
        })
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Password',
            'autocomplete': 'new-password'
        })
        self.fields['password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Confirm password',
            'autocomplete': 'new-password'
        })
    
    def clean_username(self):
        username = self.cleaned_data.get('username')
        if username:
            # Sanitizar entrada
            username = html.escape(username.strip())
            
            # Validar caracteres permitidos
            if not re.match(r'^[a-zA-Z0-9_@\.\+\-]+$', username):
                raise ValidationError("Username can only contain letters, numbers, and @/./+/-/_ characters.")
            
            # Verificar longitud
            if len(username) < 3:
                raise ValidationError("Username must be at least 3 characters long.")
            
            if len(username) > 150:
                raise ValidationError("Username cannot exceed 150 characters.")
            
            # Verificar unicidad
            if User.objects.filter(username__iexact=username).exists():
                raise ValidationError("A user with this username already exists.")
        
        return username
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email:
            # Verificar unicidad
            if User.objects.filter(email__iexact=email).exists():
                raise ValidationError("A user with this email already exists.")
        
        return email

class UserProfileForm(forms.Form):
    """Formulario seguro para actualizar perfil de usuario"""
    
    first_name = SecureCharField(
        max_length=30,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'First name'
        })
    )
    last_name = SecureCharField(
        max_length=30,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Last name'
        })
    )
    email = SecureEmailField(
        max_length=254,
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Email address'
        })
    )
    phone = forms.CharField(
        max_length=20,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Phone number'
        })
    )
    address = SecureTextareaField(
        max_length=500,
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Address'
        })
    )
    
    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        if phone:
            # Limpiar el teléfono
            phone = re.sub(r'[^\d\+\-\(\)\s]', '', phone.strip())
            
            # Validar formato
            if not re.match(r'^[\+]?[\d\s\-\(\)]{7,20}$', phone):
                raise ValidationError("Please enter a valid phone number.")
        
        return phone

class OrderForm(forms.ModelForm):
    """Formulario seguro para actualizar órdenes"""
    
    shipping_address = SecureTextareaField(
        max_length=500,
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control', 
            'rows': 3,
            'placeholder': 'Shipping address'
        })
    )
    
    class Meta:
        model = Order
        fields = ['status', 'shipping_address']
        widgets = {
            'status': forms.Select(attrs={'class': 'form-select'}),
        }

class OrderItemForm(forms.ModelForm):
    """Formulario seguro para añadir/editar ítems de una orden"""
    
    class Meta:
        model = OrderItem
        fields = ['product', 'quantity']
        widgets = {
            'product': forms.Select(attrs={'class': 'form-select'}),
            'quantity': forms.NumberInput(attrs={
                'class': 'form-control', 
                'min': 1,
                'max': 999
            }),
        }
    
    def clean_quantity(self):
        quantity = self.cleaned_data.get('quantity')
        if quantity is not None:
            if quantity <= 0:
                raise ValidationError("Quantity must be greater than 0.")
            if quantity > 999:
                raise ValidationError("Quantity cannot exceed 999.")
        return quantity