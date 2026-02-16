import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

const MAX_ATTACHMENT_BASE64_LENGTH = 14 * 1024 * 1024
const MAX_BODY_SIZE = 15 * 1024 * 1024
const MAX_SUBJECT_LENGTH = 500
const MAX_FILENAME_LENGTH = 255
const MAX_HTML_LENGTH = 512 * 1024

function hasCRLF(s: string): boolean {
  return /[\r\n]/.test(s)
}

function sanitizeFilename(name: string): string {
  return name.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, MAX_FILENAME_LENGTH)
}

// --- Gmail API via Service Account ---

function base64url(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64urlStr(str: string): string {
  return base64url(new TextEncoder().encode(str))
}

async function importPrivateKey(pem: string): Promise<CryptoKey> {
  const pemBody = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s/g, '')
  const binaryDer = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0))
  return crypto.subtle.importKey(
    'pkcs8', binaryDer, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']
  )
}

async function getGmailAccessToken(serviceEmail: string, privateKeyPem: string, sendAs: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const header = base64urlStr(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))
  const payload = base64urlStr(JSON.stringify({
    iss: serviceEmail,
    sub: sendAs,
    scope: 'https://www.googleapis.com/auth/gmail.send',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  }))
  const signingInput = `${header}.${payload}`
  const key = await importPrivateKey(privateKeyPem)
  const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(signingInput)))
  const jwt = `${signingInput}.${base64url(sig)}`

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`,
  })
  if (!tokenRes.ok) {
    const err = await tokenRes.text()
    throw new Error(`Google token exchange failed: ${err}`)
  }
  const tokenData = await tokenRes.json()
  return tokenData.access_token
}

function buildRfc822Message(
  from: string, to: string, subject: string, html: string,
  replyTo?: string, attachmentBase64?: string, attachmentFilename?: string
): string {
  const boundary = `boundary_${crypto.randomUUID()}`
  const lines: string[] = []

  lines.push(`From: ${from}`)
  lines.push(`To: ${to}`)
  lines.push(`Subject: ${subject}`)
  if (replyTo) lines.push(`Reply-To: ${replyTo}`)
  lines.push('MIME-Version: 1.0')

  if (attachmentBase64 && attachmentFilename) {
    lines.push(`Content-Type: multipart/mixed; boundary="${boundary}"`)
    lines.push('')
    lines.push(`--${boundary}`)
    lines.push('Content-Type: text/html; charset="UTF-8"')
    lines.push('')
    lines.push(html)
    lines.push(`--${boundary}`)
    lines.push(`Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document`)
    lines.push(`Content-Disposition: attachment; filename="${attachmentFilename}"`)
    lines.push('Content-Transfer-Encoding: base64')
    lines.push('')
    // Break base64 into 76-char lines per RFC 2045
    for (let i = 0; i < attachmentBase64.length; i += 76) {
      lines.push(attachmentBase64.slice(i, i + 76))
    }
    lines.push(`--${boundary}--`)
  } else {
    lines.push('Content-Type: text/html; charset="UTF-8"')
    lines.push('')
    lines.push(html)
  }

  return lines.join('\r\n')
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const contentLength = req.headers.get('content-length')
    if (contentLength && parseInt(contentLength, 10) > MAX_BODY_SIZE) {
      return new Response(JSON.stringify({ error: 'Request too large' }), {
        status: 413,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

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

    // Verify Gmail config
    const serviceEmail = Deno.env.get('GOOGLE_SERVICE_ACCOUNT_EMAIL')
    const privateKey = Deno.env.get('GOOGLE_PRIVATE_KEY')
    const sendAs = Deno.env.get('GMAIL_SEND_AS')
    if (!serviceEmail || !privateKey || !sendAs) {
      return new Response(JSON.stringify({ error: 'Gmail service account not configured' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const body = await req.json()

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

    if (!to || !subject || !html) {
      return new Response(JSON.stringify({ error: 'Missing required fields: to, subject, html' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (typeof to !== 'string' || typeof subject !== 'string' || typeof html !== 'string') {
      return new Response(JSON.stringify({ error: 'Invalid field types' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

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

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(to)) {
      return new Response(JSON.stringify({ error: 'Invalid recipient email' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (typeof attachmentBase64 === 'string' && attachmentBase64.length > MAX_ATTACHMENT_BASE64_LENGTH) {
      return new Response(JSON.stringify({ error: 'Attachment too large (max 10 MB)' }), {
        status: 413,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Get Gmail access token via service account
    const accessToken = await getGmailAccessToken(serviceEmail, privateKey, sendAs)

    // Build RFC 822 email message
    const validReplyTo = typeof replyTo === 'string' && emailRegex.test(replyTo) ? replyTo : undefined
    const safeFilename = typeof attachmentFilename === 'string' ? sanitizeFilename(attachmentFilename) : undefined
    const rawMessage = buildRfc822Message(
      sendAs, to, subject, html, validReplyTo,
      typeof attachmentBase64 === 'string' && attachmentBase64.length > 0 ? attachmentBase64 : undefined,
      safeFilename
    )

    // Base64url-encode the message for Gmail API
    const rawBase64 = base64url(new TextEncoder().encode(rawMessage))

    // Send via Gmail API
    const gmailRes = await fetch(
      `https://gmail.googleapis.com/gmail/v1/users/${encodeURIComponent(sendAs)}/messages/send`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
        },
        body: JSON.stringify({ raw: rawBase64 }),
      }
    )

    if (!gmailRes.ok) {
      const errBody = await gmailRes.json().catch(() => ({}))
      return new Response(JSON.stringify({ error: 'Gmail send failed', detail: errBody.error?.message || gmailRes.statusText }), {
        status: 502,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const result = await gmailRes.json()

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
