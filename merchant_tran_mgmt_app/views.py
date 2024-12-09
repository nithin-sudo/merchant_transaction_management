from django.shortcuts import render, redirect
from django.contrib.auth.hashers import check_password
from .models import User  # Import your custom User model
from django.http import JsonResponse
from django_datatables_view.base_datatable_view import BaseDatatableView
from .models import Order, Merchant , OrderDetail,Customer,Product
import logging
from django.shortcuts import get_object_or_404
from datetime import datetime
import re
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
import json
from django.db.models import Sum
from django.db.models.functions import TruncDay
from django.db.models import Count
from datetime import datetime, timedelta
from django.conf import settings
import stripe
from django.utils.timezone import now
import random



import random
from datetime import datetime





def landing_page(request):
    
    return render(request, 'merchant_tran_mgmt_app/landing_page.html')



def order_confirmation_view(request, order_id):
    # Fetch the order and related data
    order = Order.objects.get(order_id=order_id)
    order_details = OrderDetail.objects.filter(order_id=order.order_id)
    customer = Customer.objects.get(customer_id=order.customer_id)

    # Prepare context for rendering
    context = {
        "order": order,
        "order_details": order_details,
        "customer": customer,
    }
    return render(request, "merchant_tran_mgmt_app/order_confirmation.html", context)




def generate_order_id(merchant_id):
    year = datetime.now().year
    random_number = random.randint(1000, 9999)
    return f"ORD{merchant_id}{year}{random_number}"


def order_confirmation(request, order_id):
    """Display order confirmation details."""
    try:
        # Fetch the order using the correct field
        order = Order.objects.get(order_id=order_id)

        # Fetch related customer information
        customer = order.customer

        # Fetch all order details
        order_details = OrderDetail.objects.filter(order=order)

        # Fetch product details for each order detail
        products = [
            {
                'product_name': Product.objects.get(product_id=detail.product_id).product_name,
                'quantity': detail.quantity,
                'price': detail.price,
            }
            for detail in order_details
        ]

        # Render the order confirmation page with all the data
        return render(request, 'merchant_tran_mgmt_app/order_confirmation.html', {
            'order': order,
            'customer': customer,
            'order_details': products,  # Pass product details with quantities
        })

    except Order.DoesNotExist:
        return JsonResponse({'error': 'Order not found.'}, status=404)




def success_view(request):
    # Retrieve data from the session
    customer_info = request.session.get('customer_info')
    merchant_id = request.session.get('merchant_id')
    products = request.session.get('products', [])
    total_amount = request.session.get('total_amount')

    if not all([customer_info, merchant_id, products, total_amount]):
        return JsonResponse({'error': 'Session data missing'}, status=400)

    # Generate Order Reference
    year = now().year
    random_number = random.randint(1000, 9999)
    order_reference = f"ORD{merchant_id}{year}{random_number}"

    # Insert Customer Data
    customer = Customer.objects.create(
        first_name=customer_info["first_name"],
        last_name=customer_info["last_name"],
        street=customer_info["street"],
        city=customer_info["city"],
        state=customer_info["state"],
        zip_code=customer_info["zip_code"],
        phone=customer_info["phone"],
        created_at=now(),
        updated_at=now(),
    )

    # Insert Order Data
    order = Order.objects.create(
        order_reference=order_reference,
        order_amount=total_amount/100,
        status="Delivered",  # Dummy scenario; no delivery partner
        created_at=now(),
        updated_at=now(),
        customer_id=customer.customer_id,
        merchant_id=merchant_id,
    )

    # Insert Order Details for Each Product
    for product in products:
        OrderDetail.objects.create(
            order_id=order.order_id,
            product_id=product["product_id"],
            quantity=product["quantity"],
            price=product["price"],
            refund="N",  # Default refund status
            created_at=now(),
            updated_at=now(),
        )


        # Pass the order reference to the success page
    context = {
        "order_reference": order_reference,
        "order_id": order.order_id,
    }

    # Redirect to Order Confirmation
    #return redirect('merchant_tran_mgmt_app/success.html', order_id=order.order_id)
    return render(request, "merchant_tran_mgmt_app/success.html", context)


def cancel_view(request):
    return render(request, 'merchant_tran_mgmt_app/cancel.html')


def stripe_checkout(request):
    """
    Render the checkout page with the Stripe publishable key.
    """
    return render(request, "merchant_tran_mgmt_app/checkout.html", {
        "stripe_publishable_key": settings.STRIPE_PUBLISHABLE_KEY,
    })


stripe.api_key = settings.STRIPE_SECRET_KEY

@csrf_exempt
def create_checkout_session(request):
    success_url = request.build_absolute_uri('/success/')
    cancel_url = request.build_absolute_uri('/cancel/')
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            amount = data.get('amount', 0) * 100  # Stripe uses cents
            customer = data.get('customer', {})
            merchant_id = data.get('merchant_id')
            products = data.get('products', [])

            # Store the data in the session
            request.session['customer_info'] = customer
            request.session['merchant_id'] = merchant_id
            request.session['products'] = products
            request.session['total_amount'] = amount
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[
                    {
                        'price_data': {
                            'currency': 'usd',
                            'product_data': {
                                'name': "Order Payment",
                            },
                            'unit_amount': int(amount),
                        },
                        'quantity': 1,
                    },
                ],
                mode='payment',
                success_url= success_url,
                cancel_url= cancel_url,
            )
            print("session")
            print(session)
            return JsonResponse({'sessionId': session.id})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)


def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        
        # Try to fetch the user from the database
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            # If the username does not exist, return a specific error
            return JsonResponse({'success': False, 'error_message': 'Username is incorrect'})

        # Check if the password is correct
        if check_password(password, user.password):
            request.session['user_id'] = user.user_id
            request.session['user_role'] = user.role
            # Return a JSON response indicating success
            return JsonResponse({'success': True, 'redirect_url': '/dashboard/'})
        else:
            # If the username exists but the password is wrong, return a specific error
            return JsonResponse({'success': False, 'error_message': 'Password is incorrect'})

    # Render the login template for GET requests
    return render(request, 'merchant_tran_mgmt_app/login.html')


def dashboard(request):
    if 'user_id' not in request.session:
        return redirect('login')
    
    # Fetch merchants for the dropdown if the user is super-admin
    merchants = []
    if request.session.get('user_role') == 'super-admin':
        merchants = list(Merchant.objects.values('merchant_id', 'business_name'))

    return render(request, 'merchant_tran_mgmt_app/dashboard.html', {'merchants': merchants})



def orders(request):
    if 'user_id' not in request.session:
        return redirect('login')
    
    context = {}

    # Include merchants if the user is a super-admin
    if request.session.get('user_role') == 'super-admin':
        merchants = Merchant.objects.values('merchant_id', 'business_name')
        context['merchants'] = merchants

    return render(request, 'merchant_tran_mgmt_app/orders.html', context)

def refunds(request):
    if 'user_id' not in request.session:
        return redirect('login')
    return render(request, 'merchant_tran_mgmt_app/refunds.html')

def users(request):
    """
    View function to render the Users page for super-admins.
    """
    # Check if the user is a super-admin
    if request.session.get('user_role') != 'super-admin':
        return redirect('dashboard')  # Redirect to dashboard if not a super-admin

    return render(request, 'merchant_tran_mgmt_app/users.html')  # Render the Users page


@csrf_exempt
def create_user(request):
    # Only super-admins can access this function
    if request.session.get('user_role') != 'super-admin':
        return redirect('dashboard')

    if request.method == 'POST':
        # Extract form data
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()
        role = request.POST.get('role', 'super-admin').strip()  # Default role

        errors = {}

        # Username validation
        username_error = validate_username(username)
        if username_error:
            errors['username'] = username_error

        # Email validation
        email_error = validate_email_format(email)
        if email_error:
            errors['email'] = email_error

        # Password validation
        if not validate_password(password):
            errors['password'] = "Password must be at least 8 characters long, include uppercase, lowercase, a number, and a special character."

        # If there are validation errors, return them
        if errors:
            return JsonResponse({'errors': errors}, status=400)

        # Hash the password
        hashed_password = make_password(password)

        # Save the user
        user = User.objects.create(
            username=username,
            email=email,
            password=hashed_password,
            role=role
        )
        return JsonResponse({'message': 'User created successfully!'})

    states = get_us_states()
    return render(request, 'merchant_tran_mgmt_app/create_user.html', {'states': states})


# Helper Functions
def validate_username(username):
    """Validates the username."""
    if not username:
        return "Username is required."
    if len(username) <= 3:
        return "Username must be at least 4 characters long."
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return "Username can only contain letters, numbers, and underscores."
    if User.objects.filter(username=username).exists():
        return "This username is already taken."
    return None


def validate_email_format(email):
    """Validates the email format."""
    if not email:
        return "Email is required."
    try:
        validate_email(email)
    except ValidationError:
        return "Invalid email format."
    if User.objects.filter(email=email).exists():
        return "This email is already registered."
    return None


def validate_password(password):
    """Validates the password strength."""
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return bool(re.match(pattern, password))

@csrf_exempt
def create_merchant_user(request):
    
    if request.session.get('user_role') != 'super-admin':
        return redirect('dashboard')

    if request.method == 'POST':
        # Merchant fields
        username = request.POST.get('username', "").strip()
        email = request.POST.get('email', "").strip()
        password = request.POST.get('password', "").strip()
        business_name = request.POST.get('business_name', "").strip()
        street = request.POST.get('street', "").strip()
        city = request.POST.get('city', "").strip()
        state = request.POST.get('state', "").strip()
        zip_code = request.POST.get('zip_code', "").strip()

        errors = {}

        # Validate username using your helper function
        username_error = validate_username(username)
        if username_error:
            errors['username'] = username_error

        # Validate email using your helper function
        email_error = validate_email_format(email)
        if email_error:
            errors['email'] = email_error

        # Validate password using your helper function
        if not validate_password(password):
            errors['password'] = (
                "Password must be at least 8 characters long, include uppercase, "
                "lowercase, a number, and a special character."
            )

        # Validate business name
        if not business_name or len(business_name) < 5:
            errors['business_name'] = "Business name must be at least 5 characters long."

        # Validate street, city, state, and zip code
        if not street:
            errors['street'] = "Street is required."
        if not city:
            errors['city'] = "City is required."
        
        if state not in [s['code'] for s in get_us_states()]:
            errors['state'] = "Invalid state selection."

        if not validate_zip_code(zip_code):
            errors['zip_code'] = "Invalid zip code format. Must be 5 digits."

        # If there are validation errors, return them
        if errors:
            return JsonResponse({'errors': errors}, status=400)

        # Hash the password
        hashed_password = make_password(password)

        # Save the User and Merchant
        user = User(username=username, email=email, password=hashed_password, role='merchant')
        user.save()

        merchant = Merchant(
            user=user,
            business_name=business_name,
            street=street,
            city=city,
            state=state,
            zip_code=zip_code,
            active='Y'
        )
        merchant.save()

        return JsonResponse({'message': 'Merchant user created successfully!'})

    # On GET, render the form with states passed as context
    states = get_us_states()
    return render(request, 'merchant_tran_mgmt_app/create_user.html', {'states': states})


# Helper Function for Zip Code Validation
def validate_zip_code(zip_code):
    """Validates the zip code format."""
    import re
    pattern = r"^\d{5}$"
    return bool(re.match(pattern, zip_code))


def get_us_states():
    """Returns a list of valid US states with their codes and full names."""
    return [
        {'code': 'AL', 'name': 'Alabama'},
        {'code': 'AK', 'name': 'Alaska'},
        {'code': 'AZ', 'name': 'Arizona'},
        {'code': 'AR', 'name': 'Arkansas'},
        {'code': 'CA', 'name': 'California'},
        {'code': 'CO', 'name': 'Colorado'},
        {'code': 'CT', 'name': 'Connecticut'},
        {'code': 'DE', 'name': 'Delaware'},
        {'code': 'FL', 'name': 'Florida'},
        {'code': 'GA', 'name': 'Georgia'},
        {'code': 'HI', 'name': 'Hawaii'},
        {'code': 'ID', 'name': 'Idaho'},
        {'code': 'IL', 'name': 'Illinois'},
        {'code': 'IN', 'name': 'Indiana'},
        {'code': 'IA', 'name': 'Iowa'},
        {'code': 'KS', 'name': 'Kansas'},
        {'code': 'KY', 'name': 'Kentucky'},
        {'code': 'LA', 'name': 'Louisiana'},
        {'code': 'ME', 'name': 'Maine'},
        {'code': 'MD', 'name': 'Maryland'},
        {'code': 'MA', 'name': 'Massachusetts'},
        {'code': 'MI', 'name': 'Michigan'},
        {'code': 'MN', 'name': 'Minnesota'},
        {'code': 'MS', 'name': 'Mississippi'},
        {'code': 'MO', 'name': 'Missouri'},
        {'code': 'MT', 'name': 'Montana'},
        {'code': 'NE', 'name': 'Nebraska'},
        {'code': 'NV', 'name': 'Nevada'},
        {'code': 'NH', 'name': 'New Hampshire'},
        {'code': 'NJ', 'name': 'New Jersey'},
        {'code': 'NM', 'name': 'New Mexico'},
        {'code': 'NY', 'name': 'New York'},
        {'code': 'NC', 'name': 'North Carolina'},
        {'code': 'ND', 'name': 'North Dakota'},
        {'code': 'OH', 'name': 'Ohio'},
        {'code': 'OK', 'name': 'Oklahoma'},
        {'code': 'OR', 'name': 'Oregon'},
        {'code': 'PA', 'name': 'Pennsylvania'},
        {'code': 'RI', 'name': 'Rhode Island'},
        {'code': 'SC', 'name': 'South Carolina'},
        {'code': 'SD', 'name': 'South Dakota'},
        {'code': 'TN', 'name': 'Tennessee'},
        {'code': 'TX', 'name': 'Texas'},
        {'code': 'UT', 'name': 'Utah'},
        {'code': 'VT', 'name': 'Vermont'},
        {'code': 'VA', 'name': 'Virginia'},
        {'code': 'WA', 'name': 'Washington'},
        {'code': 'WV', 'name': 'West Virginia'},
        {'code': 'WI', 'name': 'Wisconsin'},
        {'code': 'WY', 'name': 'Wyoming'},
    ]



def logout_view(request):
    # Flush the session to log out the user
    request.session.flush()
    return redirect('login')



def get_order(request, order_id):
    """
    Fetch order details for editing.
    """
    order = get_object_or_404(Order, order_id=order_id)
    return JsonResponse({
        'order_id': order.order_id,
        'order_reference': order.order_reference,
        'merchant_name': order.merchant.business_name,
        'customer_name': order.customer.first_name,
        'order_amount': order.order_amount,
        'status': order.status,
    })


def update_order(request, order_id):
    """
    Handles the update of order status.
    """
    if request.method == 'POST':
        try:
            # Get the order based on the order_id
            order = Order.objects.get(order_id=order_id)
            
            # Get the new status from the request
            status = request.POST.get('status')

            if status:
                # Update the status
                order.status = status
                order.save()
                return JsonResponse({'message': 'Order Status updated successfully!'}, status=200)
            else:
                return JsonResponse({'message': 'Invalid status provided!'}, status=400)
        
        except Order.DoesNotExist:
            return JsonResponse({'message': 'Order not found!'}, status=404)
    else:
        return JsonResponse({'message': 'Invalid request method!'}, status=405)
    
def get_order_details(request, order_id):
    try:
        order = Order.objects.get(order_id=order_id)
        order_details = OrderDetail.objects.filter(order_id=order_id).select_related('product')

        details = [
            {
                "product_name": detail.product.product_name,
                "quantity": detail.quantity,
                "price": float(detail.price),
                "subtotal": float(detail.price * detail.quantity),
            }
            for detail in order_details
        ]

        response = {
            "order_reference": order.order_reference,
            "customer_name": f"{order.customer.first_name} {order.customer.last_name}",
            "merchant_name": order.merchant.business_name,
            "total_amount": float(order.order_amount),
            "details": details,
        }
        return JsonResponse(response, status=200)
    except Order.DoesNotExist:
        return JsonResponse({"error": "Order not found"}, status=404)

def get_merchants(request):
    """
    Fetch the list of merchants for admin dropdown.
    """
    merchants = Merchant.objects.all().values('merchant_id', 'business_name')  # Use merchant_id
    results = [{'id': merchant['merchant_id'], 'text': merchant['business_name']} for merchant in merchants]
    return JsonResponse({'results': results})


def filter_orders(request):
    from django.db.models import Count

    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    merchant_id = request.GET.get('merchant_id')
    user_role = request.session.get('user_role')

    if not start_date or not end_date:
        return JsonResponse({'error': 'Start date and end date are required.'}, status=400)

    try:
        # Parse dates
        start_date = datetime.strptime(start_date, '%m/%d/%Y').date()
        end_date = datetime.strptime(end_date, '%m/%d/%Y').date()

        # Filter orders based on user role and filters
        if user_role == 'super-admin' and merchant_id:
            orders = Order.objects.filter(
                merchant_id=merchant_id,
                created_at__date__range=(start_date, end_date)
            )
        elif user_role == 'merchant':
            user_id = request.session.get('user_id')
            merchant = Merchant.objects.get(user_id=user_id)
            orders = Order.objects.filter(
                merchant_id=merchant.merchant_id,
                created_at__date__range=(start_date, end_date)
            )
        else:
            orders = Order.objects.filter(created_at__date__range=(start_date, end_date))

        # Count total records
        total_records = Order.objects.count()
        filtered_records = orders.count()

        # Prepare response data
        data = list(orders.values(
            'order_id',
            'order_reference',
            'merchant__business_name',
            'customer__first_name',
            'order_amount',
            'status',
            'created_at'
        ))

        # Return DataTable-compatible JSON
        return JsonResponse({
            "draw": int(request.GET.get('draw', 1)),  # Optional: DataTables draw counter
            "recordsTotal": total_records,
            "recordsFiltered": filtered_records,
            "data": data
        })

    except Exception as e:
        print(f"Error: {e}")
        return JsonResponse({'error': 'Something went wrong.'}, status=500)



@csrf_exempt
def update_merchant_status(request, merchant_id):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            action = data.get('action')
            merchant = Merchant.objects.get(pk=merchant_id)

            if action == 'deactivate':
                merchant.active = 'N'
            elif action == 'activate':
                merchant.active = 'Y'
            else:
                return JsonResponse({'error': 'Invalid action'}, status=400)

            merchant.save()
            return JsonResponse({'message': 'Merchant status updated successfully.'})
        except Merchant.DoesNotExist:
            return JsonResponse({'error': 'Merchant not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Invalid request method'}, status=405)


from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
from .models import User, Merchant

@csrf_exempt
def delete_user(request, user_id):
    """
    Deletes a user record.
    - If the user is a `merchant`, delete both `user` and `merchant` records.
    - If the user is a `super-admin`, only delete the `user` record.
    """
    if request.method == 'DELETE':
        try:
            # Fetch the user
            user = User.objects.get(pk=user_id)

            if user.role.lower() == 'merchant':
                # Delete the Merchant record first
                try:
                    with transaction.atomic():
                        Merchant.objects.filter(user_id=user.user_id).delete()
                        user.delete()
                except Exception as e:
                    return JsonResponse({'error': f'Failed to delete merchant: {str(e)}'}, status=500)
            else:
                # For non-merchant (e.g., super-admin), only delete the user record
                try:
                    user.delete()
                except Exception as e:
                    return JsonResponse({'error': f'Failed to delete user: {str(e)}'}, status=500)

            return JsonResponse({'message': 'User deleted successfully!'})
        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def change_password(request, user_id):
    """
    Handles password change requests for a user.
    """
    if request.method == 'POST':
        try:
            # Parse the JSON request data
            data = json.loads(request.body)
            new_password = data.get('newPassword')
            confirm_password = data.get('confirmPassword')
            
            # Check if passwords match
            if new_password != confirm_password:
                return JsonResponse({'error': 'Passwords do not match.'}, status=400)

            # Validate password format
            if not validate_password(new_password):
                return JsonResponse({
                    'error': 'Invalid password format. Password must be at least 8 characters long and include uppercase, lowercase, a number, and a special character.'
                }, status=400)
            
            # Fetch the user and update the password
            user = User.objects.get(pk=user_id)
            user.password = make_password(new_password)
            user.save()

            return JsonResponse({'message': 'Password changed successfully.'})
        
        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found.'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Invalid request method.'}, status=405)



@csrf_exempt
def dashboard_metrics(request):
    user_role = request.session.get('user_role')
    user_id = request.session.get('user_id')

    try:
        merchant_id = request.GET.get('merchant_id')  # Get the selected merchant ID (if any)

        if user_role == 'super-admin':
            # If no merchant is selected, use the first merchant as default
            if not merchant_id:
                first_merchant = Merchant.objects.order_by('merchant_id').first()
                if not first_merchant:
                    return JsonResponse({
                        'total_orders': 0,
                        'total_sales': 0,
                        'total_customers': 0,
                    })
                merchant_id = first_merchant.merchant_id

            # Fetch metrics for the selected merchant
            merchant = Merchant.objects.get(merchant_id=merchant_id)
            total_orders = Order.objects.filter(merchant=merchant).count()
            total_sales = Order.objects.filter(merchant=merchant).aggregate(Sum('order_amount'))['order_amount__sum'] or 0
            total_customers = Customer.objects.filter(order__merchant=merchant).distinct().count()

        elif user_role == 'merchant':
            # Fetch metrics for the logged-in merchant
            merchant = Merchant.objects.get(user_id=user_id)
            total_orders = Order.objects.filter(merchant=merchant).count()
            total_sales = Order.objects.filter(merchant=merchant).aggregate(Sum('order_amount'))['order_amount__sum'] or 0
            total_customers = Customer.objects.filter(order__merchant=merchant).distinct().count()

        else:
            return JsonResponse({'error': 'Unauthorized access'}, status=403)

        # Respond with only the metrics
        return JsonResponse({
            'total_orders': total_orders,
            'total_sales': total_sales,
            'total_customers': total_customers,
        })

    except Merchant.DoesNotExist:
        return JsonResponse({'error': 'Merchant not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    




@csrf_exempt
def last_7_days_chart(request):
    user_role = request.session.get('user_role')
    user_id = request.session.get('user_id')

    try:
        merchant_id = request.GET.get('merchant_id')  # Get the merchant_id from the request
        print(merchant_id)
        today = datetime.now().date()   
        seven_days_ago = today - timedelta(days=6)  # Include today and the past 6 days

        if user_role == 'super-admin':
            if not merchant_id:
                return JsonResponse({'error': 'Merchant ID is required for super-admin.'}, status=400)

            merchant = Merchant.objects.get(merchant_id=merchant_id)
        elif user_role == 'merchant':
            merchant = Merchant.objects.get(user_id=user_id)
        else:
            return JsonResponse({'error': 'Unauthorized access'}, status=403)

        # Query to get daily order counts for the last 7 days
        order_data = (
            Order.objects.filter(merchant=merchant, created_at__date__gte=seven_days_ago)
            .annotate(day=TruncDay('created_at'))
            .values('day')
            .annotate(order_count=Count('order_id'))  # Use the correct field name here
            .order_by('day')
        )

        print(order_data)
        if not order_data.exists():
            return JsonResponse({'chart_data': [], 'message': 'No orders available for the last 7 days.'})


        # Format the response for the chart
        chart_data = [{'date': data['day'].strftime('%Y-%m-%d'), 'orders': data['order_count']} for data in order_data]

        return JsonResponse({'chart_data': chart_data})
    except Merchant.DoesNotExist:
        return JsonResponse({'error': 'Merchant not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)






# views.py
def dummy_checkout(request):
    """
    Render the dummy checkout page with necessary data.
    """
    merchants = Merchant.objects.all().values('merchant_id', 'business_name')
    products = Product.objects.all().values('product_id', 'product_name', 'price')
    us_states = get_us_states()  # Use the function to fetch states

    return render(request, 'merchant_tran_mgmt_app/dummy_checkout.html', {
        'merchants': merchants,
        'products': products,
        'us_states': us_states,
        'stripe_publishable_key': settings.STRIPE_PUBLISHABLE_KEY,
    })



class OrderListView(BaseDatatableView):
    
    """
    A simplified class-based view for serving order data to DataTables.
    """
    model = Order  # Model to fetch data from

    # Define columns to display in the DataTable
    columns = [
        'order_id',  # Order ID
        'order_reference',  # Order Reference
        'merchant__business_name',  # Merchant Business Name (related field)
        'customer__first_name',  # Customer First Name (related field)
        'order_amount',  # Order Amount
        'status',  # Order Status
        'created_at',  # Created At (timestamp)
        'actions',  # Action column for Edit/Delete buttons
    ]

    def get_initial_queryset(self):
        """
        Return orders based on the user's role.
        """
        user_role = self.request.session.get('user_role')  # Get the user role from the session
        user_id = self.request.session.get('user_id')  # Retrieve the user_id from the session

        if user_role == 'super-admin':
            # Super-admins can see all orders
            return Order.objects.select_related('merchant', 'customer').all()
        elif user_role == 'merchant':
            # Merchants can see only their own orders
            try:
                merchant = Merchant.objects.get(user_id=user_id)  # Find the merchant linked to the user
                return Order.objects.filter(merchant_id=merchant.merchant_id)
            except Merchant.DoesNotExist:
                return Order.objects.none()  # No orders if merchant is not found
        else:
            # No access for other roles
            return Order.objects.none()

    def render_column(self, row, column):

        logger = logging.getLogger(__name__)
        logger.info(self.render_column)
        logger.info(column)
        """
        Customize how columns are rendered in the DataTable.
        """
        if column == 'merchant__business_name':
            # Fetch and display the merchant's business name
            return row.merchant.business_name
        elif column == 'customer__first_name':
            # Fetch and display the customer's full name
            return row.customer.first_name
        elif column == 'created_at':
            # Format the date as "MM/DD/YYYY HH:MM:SS"
            return row.created_at.strftime('%Y-%m-%d %H:%M:%S') if row.created_at else '-'
        elif column == 'actions':
            # Add an Edit button (you can later add Delete functionality here too)
            return f'''
                <button class="btn btn-primary btn-sm btn-edit" data-id="{row.order_id}">Edit</button>
            '''
        return super().render_column(row, column)
    
    def paginate_queryset(self, qs):
        """
        Handle simple pagination, starting with 5 records per page.
        """
        # Get pagination parameters from the frontend
        start = int(self.request.GET.get('start', 0))  # Starting record index
        length = int(self.request.GET.get('length', 5))  # Number of records per page (default 5)

        # Use Django's Paginator for pagination
        paginator = Paginator(qs, length)  # Divide queryset into pages of size `length`
        current_page = (start // length) + 1  # Calculate the current page number

        try:
            page = paginator.page(current_page)  # Get the current page
            return page.object_list  # Return the paginated records
        except Exception as e:
            return qs.none()  # Return an empty queryset if pagination fails

class UserListView(BaseDatatableView):
    """
    Class-based view for fetching user data for DataTables.
    """
    model = User  # User model

    # Define columns to display in the DataTable
    columns = [
        'user_id',             # User ID
        'username',            # Username
        'email',               # Email
        'role',                # Role (e.g., 'super-admin' or 'merchant')
        'created_at',          # Creation timestamp
        'actions',             # Action buttons (e.g., Deactivate, Edit)
    ]

    def get_initial_queryset(self):
        """
        Return users based on filtering conditions.
        Only 'super-admin' should access this data.
        """
        user_role = self.request.session.get('user_role')  # Get the user role from session
        if user_role == 'super-admin':
            return User.objects.all()  # Allow super-admin to see all users
        return User.objects.none()  # Deny access for other roles

    def prepare_results(self, qs):
        """
        Prepare the data for the frontend DataTable.
        """
        data = []
        for item in qs:
            # Check if the user is a merchant and fetch the 'active' status
            active_status = None
            if item.role.lower() == 'merchant':
                try:
                    merchant = Merchant.objects.get(user_id=item.user_id)
                    active_status = merchant.active  # Get 'active' status from Merchant table
                except Merchant.DoesNotExist:
                    active_status = None  # Default to None if no Merchant record exists

            row = {
                'user_id': item.user_id,
                'username': item.username,
                'email': item.email,
                'role': item.role,
                'created_at': item.created_at.strftime('%Y-%m-%d %H:%M:%S') if item.created_at else '-',
                'active': active_status,  # Add 'active' status to the row
            }
            data.append(row)
        return data


    def render_column(self, row, column):
        """
        Custom rendering for specific columns.
        """
        if column == 'role':
            return row.role.title()  # Capitalize the role (e.g., 'Super-Admin', 'Merchant')
        elif column == 'created_at':
            return row.created_at.strftime('%Y-%m-%d %H:%M:%S') if row.created_at else '-'
        elif column == 'actions':
            # Initialize the Delete button (always shown for all users)
            actions = f'''
                <button class="btn btn-link btn-sm btn-delete"
                    data-id="{row.user_id}" title="Delete">
                    <i class="fas fa-trash"></i>
                </button>
            '''

            # Add the Change Password button (always shown for all users)
            actions += f'''
                <button class="btn btn-warning btn-sm btn-change-password" 
                    data-id="{row.user_id}" 
                    title="Change Password">
                    <i class="fas fa-key"></i>
                </button>
            '''

            # Add Activate/Deactivate or No Action buttons for merchants
            if row.role.lower() == 'merchant':
                merchant = Merchant.objects.filter(user_id=row.user_id).first()
                if merchant and merchant.active == 'Y':  # Active merchant
                    actions = f'''
                        <button class="btn btn-danger btn-sm btn-toggle-status"
                            data-id="{row.user_id}"
                            data-status="deactivate">
                            Deactivate
                        </button>
                    ''' + actions
                elif merchant and merchant.active == 'N':  # Inactive merchant
                    actions = f'''
                        <button class="btn btn-success btn-sm btn-toggle-status"
                            data-id="{row.user_id}"
                            data-status="activate">
                            Activate
                        </button>
                    ''' + actions
                else:
                    actions = f'''
                        <button class="btn btn-secondary btn-sm" disabled>
                            No Action
                        </button>
                    ''' + actions
            else:
                # Add No Action button for non-merchants
                actions = f'''
                    <button class="btn btn-secondary btn-sm" disabled>
                        No Action
                    </button>
                ''' + actions

            return actions
        return super().render_column(row, column)

    def paginate_queryset(self, qs):
        """
        Handle pagination for users.
        """
        start = int(self.request.GET.get('start', 0))  # Starting index
        length = int(self.request.GET.get('length', 10))  # Number of records per page

        paginator = Paginator(qs, length)  # Paginate with specified length
        current_page = (start // length) + 1  # Calculate current page number

        try:
            page = paginator.page(current_page)
            return page.object_list  # Return records for the current page
        except:
            return qs.none()  # Return empty if pagination fails





class RefundsListView(BaseDatatableView):
    """
    Class-based view for fetching refund data for the Refunds page.
    """
    model = OrderDetail  # Base model for the query
    columns = [
        'order__order_id',               # Order ID
        'order__order_reference',        # Order Reference
        'product__product_name',         # Product Name
        'order__merchant__business_name',  # Merchant Name
        'order__customer__first_name',   # Customer First Name
        'quantity',                      # Quantity
        'price'
        'created_at',                    # Date
    ]

    def get_initial_queryset(self):
        """
        Returns refunds based on user role.
        """
        user_role = self.request.session.get('user_role')
        user_id = self.request.session.get('user_id')

        if user_role == 'super-admin':
            # Super-admins can see all refunds
            return OrderDetail.objects.filter(refund='Y').select_related(
                'order', 'order__merchant', 'order__customer', 'product'
            )
        elif user_role == 'merchant':
            # Merchants can see only their own refunds
            try:
                merchant = Merchant.objects.get(user_id=user_id)
                return OrderDetail.objects.filter(
                    refund='Y', order__merchant=merchant
                ).select_related('order', 'product', 'order__customer')
            except Merchant.DoesNotExist:
                return OrderDetail.objects.none()
        else:
            # No refunds for other roles
            return OrderDetail.objects.none()

    def render_column(self, row, column):
        """
        Custom rendering for columns that are not part of the OrderDetail model.
        """
        if column == 'order__order_id':
            return row.order.order_id  # Access the related Order model's order_id
        elif column == 'order__order_reference':
            return row.order.order_reference  # Access the related Order model's order_reference
        elif column == 'product__product_name':
            return row.product.product_name  # Access the related Product model's product_name
        elif column == 'order__merchant__business_name':
            return row.order.merchant.business_name  # Access the related Merchant model's business_name
        elif column == 'order__customer__first_name':
            # Combine first name and last name for the customer
            return f"{row.order.customer.first_name} {row.order.customer.last_name}"
        elif column == 'created_at':
            # Format the date as "MM/DD/YYYY HH:MM:SS"
            return row.created_at.strftime('%Y-%m-%d %H:%M:%S') if row.created_at else '-'
        

        return super().render_column(row, column)