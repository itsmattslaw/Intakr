import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

// Max attachment size: 10 MB (base64 inflates ~33%, so check for ~14 MB of base64 text)
const MAX_ATTACHMENT_BASE64_LENGTH = 14 * 1024 * 1024
// Max overall request body size: 15 MB
const MAX_BODY_SIZE = 15 * 1024 * 1024
// Max subject / filename length
const MAX_SUBJECT_LENGTH = 500
const MAX_FILENAME_LENGTH = 255
// Max HTML body length: 500 KB
const MAX_HTML_LENGTH = 512 * 1024

// Reject strings containing CRLF / newline sequences (header injection prevention)
function hasCRLF(s: string): boolean {
  return /[\r\n]/.test(s)
}

// Sanitize attachment filename: allow only safe characters
function sanitizeFilename(name: string): string {
  return name.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, MAX_FILENAME_LENGTH)
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    // Enforce request body size limit
    const contentLength = req.headers.get('content-length')
    if (contentLength && parseInt(contentLength, 10) > MAX_BODY_SIZE) {
      return new Response(JSON.stringify({ error: 'Request too large' }), {
        status: 413,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Verify the caller is authenticated
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) {
      return new Response(JSON.stringify({ error: 'Missing authorization' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_ANON_KEY')!,
      { global: { headers: { Authorization: authHeader } } }
    )

    const { data: { user }, error: authError } = await supabase.auth.getUser()
    if (authError || !user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (!user.email?.endsWith('@margolispllc.com')) {
      return new Response(JSON.stringify({ error: 'Forbidden' }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const resendApiKey = Deno.env.get('RESEND_API_KEY')
    if (!resendApiKey) {
      return new Response(JSON.stringify({ error: 'Email service not configured' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const body = await req.json()

    // Only allow expected fields
    const allowedKeys = new Set(['to', 'subject', 'html', 'replyTo', 'attachmentBase64', 'attachmentFilename'])
    for (const key of Object.keys(body)) {
      if (!allowedKeys.has(key)) {
        return new Response(JSON.stringify({ error: 'Invalid payload field: ' + key }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }
    }

    const { to, subject, html, replyTo, attachmentBase64, attachmentFilename } = body

    // Validate required fields
    if (!to || !subject || !html) {
      return new Response(JSON.stringify({ error: 'Missing required fields: to, subject, html' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Type checks
    if (typeof to !== 'string' || typeof subject !== 'string' || typeof html !== 'string') {
      return new Response(JSON.stringify({ error: 'Invalid field types' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // CRLF injection prevention on header-sensitive fields
    if (hasCRLF(to) || hasCRLF(subject)) {
      return new Response(JSON.stringify({ error: 'Invalid characters in email fields' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }
    if (typeof replyTo === 'string' && hasCRLF(replyTo)) {
      return new Response(JSON.stringify({ error: 'Invalid characters in reply-to' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Length limits
    if (subject.length > MAX_SUBJECT_LENGTH) {
      return new Response(JSON.stringify({ error: 'Subject too long' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }
    if (html.length > MAX_HTML_LENGTH) {
      return new Response(JSON.stringify({ error: 'HTML body too large' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(to)) {
      return new Response(JSON.stringify({ error: 'Invalid recipient email' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Attachment size limit
    if (typeof attachmentBase64 === 'string' && attachmentBase64.length > MAX_ATTACHMENT_BASE64_LENGTH) {
      return new Response(JSON.stringify({ error: 'Attachment too large (max 10 MB)' }), {
        status: 413,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Sender domain — use env var or default
    const fromAddress = Deno.env.get('EMAIL_FROM_ADDRESS') || 'Margolis PLLC <noreply@margolispllc.com>'

    // Build Resend payload
    const emailPayload: Record<string, unknown> = {
      from: fromAddress,
      to: [to],
      subject,
      html,
    }

    if (typeof replyTo === 'string' && emailRegex.test(replyTo)) {
      emailPayload.reply_to = [replyTo]
    }

    // Attach DOCX if provided (with sanitized filename)
    if (typeof attachmentBase64 === 'string' && attachmentBase64.length > 0 && typeof attachmentFilename === 'string') {
      emailPayload.attachments = [{
        filename: sanitizeFilename(attachmentFilename),
        content: attachmentBase64,
      }]
    }

    const resendRes = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${resendApiKey}`,
      },
      body: JSON.stringify(emailPayload),
    })

    if (!resendRes.ok) {
      const errBody = await resendRes.json().catch(() => ({}))
      return new Response(JSON.stringify({ error: 'Email delivery failed', detail: errBody.message || resendRes.statusText }), {
        status: 502,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const result = await resendRes.json()

    return new Response(JSON.stringify({ ok: true, id: result.id }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})
