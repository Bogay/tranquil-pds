import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte'
import Notifications from '../routes/Notifications.svelte'
import {
  setupFetchMock,
  mockEndpoint,
  jsonResponse,
  errorResponse,
  mockData,
  clearMocks,
  setupAuthenticatedUser,
  setupUnauthenticatedUser,
} from './mocks'

describe('Notifications', () => {
  beforeEach(() => {
    clearMocks()
    setupFetchMock()
  })

  describe('authentication guard', () => {
    it('redirects to login when not authenticated', async () => {
      setupUnauthenticatedUser()
      render(Notifications)

      await waitFor(() => {
        expect(window.location.hash).toBe('#/login')
      })
    })
  })

  describe('page structure', () => {
    beforeEach(() => {
      setupAuthenticatedUser()
      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        jsonResponse(mockData.notificationPrefs())
      )
    })

    it('displays all page elements and sections', async () => {
      render(Notifications)

      await waitFor(() => {
        expect(screen.getByRole('heading', { name: /notification preferences/i, level: 1 })).toBeInTheDocument()
        expect(screen.getByRole('link', { name: /dashboard/i })).toHaveAttribute('href', '#/dashboard')
        expect(screen.getByText(/password resets/i)).toBeInTheDocument()
        expect(screen.getByRole('heading', { name: /preferred channel/i })).toBeInTheDocument()
        expect(screen.getByRole('heading', { name: /channel configuration/i })).toBeInTheDocument()
      })
    })
  })

  describe('loading state', () => {
    beforeEach(() => {
      setupAuthenticatedUser()
    })

    it('shows loading text while fetching preferences', async () => {
      mockEndpoint('com.bspds.account.getNotificationPrefs', async () => {
        await new Promise(resolve => setTimeout(resolve, 100))
        return jsonResponse(mockData.notificationPrefs())
      })

      render(Notifications)

      expect(screen.getByText(/loading/i)).toBeInTheDocument()
    })
  })

  describe('channel options', () => {
    beforeEach(() => {
      setupAuthenticatedUser()
    })

    it('displays all four channel options', async () => {
      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        jsonResponse(mockData.notificationPrefs())
      )

      render(Notifications)

      await waitFor(() => {
        expect(screen.getByRole('radio', { name: /email/i })).toBeInTheDocument()
        expect(screen.getByRole('radio', { name: /discord/i })).toBeInTheDocument()
        expect(screen.getByRole('radio', { name: /telegram/i })).toBeInTheDocument()
        expect(screen.getByRole('radio', { name: /signal/i })).toBeInTheDocument()
      })
    })

    it('email channel is always selectable', async () => {
      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        jsonResponse(mockData.notificationPrefs())
      )

      render(Notifications)

      await waitFor(() => {
        const emailRadio = screen.getByRole('radio', { name: /email/i })
        expect(emailRadio).not.toBeDisabled()
      })
    })

    it('discord channel is disabled when not configured', async () => {
      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        jsonResponse(mockData.notificationPrefs({ discordId: null }))
      )

      render(Notifications)

      await waitFor(() => {
        const discordRadio = screen.getByRole('radio', { name: /discord/i })
        expect(discordRadio).toBeDisabled()
      })
    })

    it('discord channel is enabled when configured', async () => {
      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        jsonResponse(mockData.notificationPrefs({ discordId: '123456789' }))
      )

      render(Notifications)

      await waitFor(() => {
        const discordRadio = screen.getByRole('radio', { name: /discord/i })
        expect(discordRadio).not.toBeDisabled()
      })
    })

    it('shows hint for disabled channels', async () => {
      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        jsonResponse(mockData.notificationPrefs())
      )

      render(Notifications)

      await waitFor(() => {
        expect(screen.getAllByText(/configure below to enable/i).length).toBeGreaterThan(0)
      })
    })

    it('selects current preferred channel', async () => {
      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        jsonResponse(mockData.notificationPrefs({ preferredChannel: 'email' }))
      )

      render(Notifications)

      await waitFor(() => {
        const emailRadio = screen.getByRole('radio', { name: /email/i }) as HTMLInputElement
        expect(emailRadio.checked).toBe(true)
      })
    })
  })

  describe('channel configuration', () => {
    beforeEach(() => {
      setupAuthenticatedUser()
    })

    it('displays email as readonly with current value', async () => {
      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        jsonResponse(mockData.notificationPrefs())
      )

      render(Notifications)

      await waitFor(() => {
        const emailInput = screen.getByLabelText(/^email$/i) as HTMLInputElement
        expect(emailInput).toBeDisabled()
        expect(emailInput.value).toBe('test@example.com')
      })
    })

    it('displays all channel inputs with current values', async () => {
      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        jsonResponse(mockData.notificationPrefs({
          discordId: '123456789',
          telegramUsername: 'testuser',
          signalNumber: '+1234567890',
        }))
      )

      render(Notifications)

      await waitFor(() => {
        expect((screen.getByLabelText(/discord user id/i) as HTMLInputElement).value).toBe('123456789')
        expect((screen.getByLabelText(/telegram username/i) as HTMLInputElement).value).toBe('testuser')
        expect((screen.getByLabelText(/signal phone number/i) as HTMLInputElement).value).toBe('+1234567890')
      })
    })
  })

  describe('verification status badges', () => {
    beforeEach(() => {
      setupAuthenticatedUser()
    })

    it('shows Primary badge for email', async () => {
      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        jsonResponse(mockData.notificationPrefs())
      )

      render(Notifications)

      await waitFor(() => {
        expect(screen.getByText('Primary')).toBeInTheDocument()
      })
    })

    it('shows Verified badge for verified discord', async () => {
      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        jsonResponse(mockData.notificationPrefs({
          discordId: '123456789',
          discordVerified: true,
        }))
      )

      render(Notifications)

      await waitFor(() => {
        const verifiedBadges = screen.getAllByText('Verified')
        expect(verifiedBadges.length).toBeGreaterThan(0)
      })
    })

    it('shows Not verified badge for unverified discord', async () => {
      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        jsonResponse(mockData.notificationPrefs({
          discordId: '123456789',
          discordVerified: false,
        }))
      )

      render(Notifications)

      await waitFor(() => {
        expect(screen.getByText('Not verified')).toBeInTheDocument()
      })
    })

    it('does not show badge when channel not configured', async () => {
      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        jsonResponse(mockData.notificationPrefs())
      )

      render(Notifications)

      await waitFor(() => {
        expect(screen.getByText('Primary')).toBeInTheDocument()
        expect(screen.queryByText('Not verified')).not.toBeInTheDocument()
      })
    })
  })

  describe('save preferences', () => {
    beforeEach(() => {
      setupAuthenticatedUser()
    })

    it('calls updateNotificationPrefs with correct data', async () => {
      let capturedBody: Record<string, unknown> | null = null

      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        jsonResponse(mockData.notificationPrefs())
      )

      mockEndpoint('com.bspds.account.updateNotificationPrefs', (_url, options) => {
        capturedBody = JSON.parse((options?.body as string) || '{}')
        return jsonResponse({ success: true })
      })

      render(Notifications)

      await waitFor(() => {
        expect(screen.getByLabelText(/discord user id/i)).toBeInTheDocument()
      })

      await fireEvent.input(screen.getByLabelText(/discord user id/i), { target: { value: '999888777' } })
      await fireEvent.click(screen.getByRole('button', { name: /save preferences/i }))

      await waitFor(() => {
        expect(capturedBody).not.toBeNull()
        expect(capturedBody?.discordId).toBe('999888777')
        expect(capturedBody?.preferredChannel).toBe('email')
      })
    })

    it('shows loading state while saving', async () => {
      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        jsonResponse(mockData.notificationPrefs())
      )

      mockEndpoint('com.bspds.account.updateNotificationPrefs', async () => {
        await new Promise(resolve => setTimeout(resolve, 100))
        return jsonResponse({ success: true })
      })

      render(Notifications)

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /save preferences/i })).toBeInTheDocument()
      })

      await fireEvent.click(screen.getByRole('button', { name: /save preferences/i }))

      expect(screen.getByRole('button', { name: /saving/i })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /saving/i })).toBeDisabled()
    })

    it('shows success message after saving', async () => {
      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        jsonResponse(mockData.notificationPrefs())
      )

      mockEndpoint('com.bspds.account.updateNotificationPrefs', () =>
        jsonResponse({ success: true })
      )

      render(Notifications)

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /save preferences/i })).toBeInTheDocument()
      })

      await fireEvent.click(screen.getByRole('button', { name: /save preferences/i }))

      await waitFor(() => {
        expect(screen.getByText(/notification preferences saved/i)).toBeInTheDocument()
      })
    })

    it('shows error when save fails', async () => {
      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        jsonResponse(mockData.notificationPrefs())
      )

      mockEndpoint('com.bspds.account.updateNotificationPrefs', () =>
        errorResponse('InvalidRequest', 'Invalid channel configuration', 400)
      )

      render(Notifications)

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /save preferences/i })).toBeInTheDocument()
      })

      await fireEvent.click(screen.getByRole('button', { name: /save preferences/i }))

      await waitFor(() => {
        expect(screen.getByText(/invalid channel configuration/i)).toBeInTheDocument()
        expect(screen.getByText(/invalid channel configuration/i).closest('.message')).toHaveClass('error')
      })
    })

    it('reloads preferences after successful save', async () => {
      let loadCount = 0

      mockEndpoint('com.bspds.account.getNotificationPrefs', () => {
        loadCount++
        return jsonResponse(mockData.notificationPrefs())
      })

      mockEndpoint('com.bspds.account.updateNotificationPrefs', () =>
        jsonResponse({ success: true })
      )

      render(Notifications)

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /save preferences/i })).toBeInTheDocument()
      })

      const initialLoadCount = loadCount
      await fireEvent.click(screen.getByRole('button', { name: /save preferences/i }))

      await waitFor(() => {
        expect(loadCount).toBeGreaterThan(initialLoadCount)
      })
    })
  })

  describe('channel selection interaction', () => {
    beforeEach(() => {
      setupAuthenticatedUser()
    })

    it('enables discord channel after entering discord ID', async () => {
      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        jsonResponse(mockData.notificationPrefs())
      )

      render(Notifications)

      await waitFor(() => {
        expect(screen.getByRole('radio', { name: /discord/i })).toBeDisabled()
      })

      await fireEvent.input(screen.getByLabelText(/discord user id/i), { target: { value: '123456789' } })

      await waitFor(() => {
        expect(screen.getByRole('radio', { name: /discord/i })).not.toBeDisabled()
      })
    })

    it('allows selecting a configured channel', async () => {
      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        jsonResponse(mockData.notificationPrefs({
          discordId: '123456789',
          discordVerified: true,
        }))
      )

      render(Notifications)

      await waitFor(() => {
        expect(screen.getByRole('radio', { name: /discord/i })).not.toBeDisabled()
      })

      await fireEvent.click(screen.getByRole('radio', { name: /discord/i }))

      const discordRadio = screen.getByRole('radio', { name: /discord/i }) as HTMLInputElement
      expect(discordRadio.checked).toBe(true)
    })
  })

  describe('error handling', () => {
    beforeEach(() => {
      setupAuthenticatedUser()
    })

    it('shows error when loading preferences fails', async () => {
      mockEndpoint('com.bspds.account.getNotificationPrefs', () =>
        errorResponse('InternalError', 'Database connection failed', 500)
      )

      render(Notifications)

      await waitFor(() => {
        expect(screen.getByText(/database connection failed/i)).toBeInTheDocument()
      })
    })
  })
})
