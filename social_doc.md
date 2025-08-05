# Social Media API Setup Guide

This guide will help you set up API access for LinkedIn and Twitter/X platforms to enable social media posting from your application.

## LinkedIn API Setup

### Step 1: Create a LinkedIn App
1. Go to [LinkedIn Developers](https://www.linkedin.com/developers/)
2. Click "Create App"
3. Fill in the required information:
   - App name: Your application name
   - LinkedIn Page: Your company page
   - App Logo: Upload your app logo
4. Click "Create App"

### Step 2: Configure App Settings
1. In your app dashboard, go to "Auth" tab
2. Add your redirect URI: `https://localhost` (for development)
3. Note down your **Client ID** and **Client Secret**

### Step 3: Get Organization ID
1. Go to your LinkedIn company page
2. The organization ID is in the URL: `https://www.linkedin.com/company/[organization-id]/`
3. The format is usually a number like `12345678`

### Step 4: Get Access Token
1. In your app dashboard, go to "Products" tab
2. Request access to "Marketing Developer Platform"
3. Once approved, go to "Auth" tab
4. Use the OAuth 2.0 flow to get an access token:
   - Visit: `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_REDIRECT_URI&scope=w_member_social`
   - Authorize the app
   - Copy the authorization code from the redirect URL
5. Exchange the code for an access token:
   ```bash
   curl -X POST https://www.linkedin.com/oauth/v2/accessToken \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=authorization_code&code=YOUR_AUTH_CODE&client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&redirect_uri=YOUR_REDIRECT_URI"
   ```

### Step 5: Configure in Your App
In your application's Platform Settings, enter:
- **Client ID**: Your LinkedIn app client ID
- **Client Secret**: Your LinkedIn app client secret
- **Organization URN**: `urn:li:organization:YOUR_ORG_ID`
- **Access Token**: The access token you obtained

## Twitter/X API Setup

### Step 1: Apply for Twitter API Access
1. Go to [Twitter Developer Portal](https://developer.twitter.com/)
2. Sign in with your Twitter account
3. Apply for a developer account (may take 1-2 days for approval)
4. Once approved, create a new app

### Step 2: Create Twitter App
1. In the developer portal, click "Create App"
2. Fill in the required information:
   - App name: Your application name
   - Use case: Select appropriate use case
3. Click "Create"

### Step 3: Configure App Settings
1. In your app dashboard, go to "Keys and Tokens" tab
2. Generate the following:
   - **API Key** (Consumer Key)
   - **API Secret** (Consumer Secret)
   - **Access Token**
   - **Access Token Secret**

### Step 4: Set App Permissions
1. Go to "App Permissions" tab
2. Set permissions to "Read and Write" for posting tweets
3. Save changes

### Step 5: Configure in Your App
In your application's Platform Settings, enter:
- **API Key**: Your Twitter app API key
- **API Secret**: Your Twitter app API secret
- **Access Token**: Your access token
- **Access Token Secret**: Your access token secret

## Required Python Packages

Install the required packages for social media posting:

```bash
pip install tweepy
```

## Testing Your Setup

### Test LinkedIn Posting
1. Create a new social post in your application
2. Check "Post to LinkedIn"
3. Save the post
4. Check your LinkedIn company page for the new post

### Test Twitter Posting
1. Create a new social post in your application
2. Check "Post to Twitter"
3. Save the post
4. Check your Twitter account for the new tweet

## Troubleshooting

### LinkedIn Issues
- **"Invalid access token"**: Your access token may have expired. Generate a new one.
- **"Organization not found"**: Verify your organization ID is correct.
- **"Insufficient permissions"**: Ensure your app has the required scopes.

### Twitter Issues
- **"Invalid credentials"**: Verify all API keys and tokens are correct.
- **"Rate limit exceeded"**: Twitter has rate limits. Wait before posting again.
- **"App not approved"**: Ensure your Twitter app is approved for the required permissions.

### General Issues
- **"Network error"**: Check your internet connection and firewall settings.
- **"API endpoint not found"**: Verify you're using the correct API endpoints.

## Security Notes

1. **Never share your API keys** publicly
2. **Store keys securely** in your application settings
3. **Rotate keys regularly** for better security
4. **Monitor API usage** to stay within limits
5. **Use environment variables** in production

## Rate Limits

### LinkedIn
- 100 posts per day per organization
- 1 post per minute

### Twitter
- 300 tweets per 3-hour window
- 25 tweets per 15-minute window

## Support

If you encounter issues:
1. Check the platform's official documentation
2. Verify your API credentials
3. Test with simple posts first
4. Check application logs for detailed error messages 