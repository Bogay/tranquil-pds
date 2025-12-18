import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte'
import Settings from '../routes/Settings.svelte'
import {
  setupFetchMock,
  mockEndpoint,
  jsonResponse,
  errorResponse,
  clearMocks,
  setupAuthenticatedUser,
  setupUnauthenticatedUser,
} from './mocks'
describe('Settings', () => {
  beforeEach(() => {
    clearMocks()
    setupFetchMock()
    window.confirm = vi.fn(() => true)
  })
  describe('authentication guard', () => {
    it('redirects to login when not authenticated', async () => {
      setupUnauthenticatedUser()
      render(Settings)
      await waitFor(() => {
        expect(window.location.hash).toBe('#/login')
      })
    })
  })
  describe('page structure', () => {
    beforeEach(() => {
      setupAuthenticatedUser()
    })
    it('displays all page elements and sections', async () => {
      render(Settings)
      await waitFor(() => {
        expect(screen.getByRole('heading', { name: /account settings/i, level: 1 })).toBeInTheDocument()
        expect(screen.getByRole('link', { name: /dashboard/i })).toHaveAttribute('href', '#/dashboard')
        expect(screen.getByRole('heading', { name: /change email/i })).toBeInTheDocument()
        expect(screen.getByRole('heading', { name: /change handle/i })).toBeInTheDocument()
        expect(screen.getByRole('heading', { name: /delete account/i })).toBeInTheDocument()
      })
    })
  })
  describe('email change', () => {
    beforeEach(() => {
      setupAuthenticatedUser()
    })
    it('displays current email and input field', async () => {
      render(Settings)
      await waitFor(() => {
        expect(screen.getByText(/current: test@example.com/i)).toBeInTheDocument()
        expect(screen.getByLabelText(/new email/i)).toBeInTheDocument()
      })
    })
    it('calls requestEmailUpdate when submitting', async () => {
      let requestCalled = false
      mockEndpoint('com.atproto.server.requestEmailUpdate', () => {
        requestCalled = true
        return jsonResponse({ tokenRequired: true })
      })
      render(Settings)
      await waitFor(() => {
        expect(screen.getByLabelText(/new email/i)).toBeInTheDocument()
      })
      await fireEvent.input(screen.getByLabelText(/new email/i), { target: { value: 'newemail@example.com' } })
      await fireEvent.click(screen.getByRole('button', { name: /change email/i }))
      await waitFor(() => {
        expect(requestCalled).toBe(true)
      })
    })
    it('shows verification code input when token is required', async () => {
      mockEndpoint('com.atproto.server.requestEmailUpdate', () =>
        jsonResponse({ tokenRequired: true })
      )
      render(Settings)
      await waitFor(() => {
        expect(screen.getByLabelText(/new email/i)).toBeInTheDocument()
      })
      await fireEvent.input(screen.getByLabelText(/new email/i), { target: { value: 'newemail@example.com' } })
      await fireEvent.click(screen.getByRole('button', { name: /change email/i }))
      await waitFor(() => {
        expect(screen.getByLabelText(/verification code/i)).toBeInTheDocument()
        expect(screen.getByRole('button', { name: /confirm email change/i })).toBeInTheDocument()
      })
    })
    it('calls updateEmail with token when confirming', async () => {
      let updateCalled = false
      let capturedBody: Record<string, string> | null = null
      mockEndpoint('com.atproto.server.requestEmailUpdate', () =>
        jsonResponse({ tokenRequired: true })
      )
      mockEndpoint('com.atproto.server.updateEmail', (_url, options) => {
        updateCalled = true
        capturedBody = JSON.parse((options?.body as string) || '{}')
        return jsonResponse({})
      })
      render(Settings)
      await waitFor(() => {
        expect(screen.getByLabelText(/new email/i)).toBeInTheDocument()
      })
      await fireEvent.input(screen.getByLabelText(/new email/i), { target: { value: 'newemail@example.com' } })
      await fireEvent.click(screen.getByRole('button', { name: /change email/i }))
      await waitFor(() => {
        expect(screen.getByLabelText(/verification code/i)).toBeInTheDocument()
      })
      await fireEvent.input(screen.getByLabelText(/verification code/i), { target: { value: '123456' } })
      await fireEvent.click(screen.getByRole('button', { name: /confirm email change/i }))
      await waitFor(() => {
        expect(updateCalled).toBe(true)
        expect(capturedBody?.email).toBe('newemail@example.com')
        expect(capturedBody?.token).toBe('123456')
      })
    })
    it('shows success message after email update', async () => {
      mockEndpoint('com.atproto.server.requestEmailUpdate', () =>
        jsonResponse({ tokenRequired: true })
      )
      mockEndpoint('com.atproto.server.updateEmail', () =>
        jsonResponse({})
      )
      render(Settings)
      await waitFor(() => {
        expect(screen.getByLabelText(/new email/i)).toBeInTheDocument()
      })
      await fireEvent.input(screen.getByLabelText(/new email/i), { target: { value: 'new@test.com' } })
      await fireEvent.click(screen.getByRole('button', { name: /change email/i }))
      await waitFor(() => {
        expect(screen.getByLabelText(/verification code/i)).toBeInTheDocument()
      })
      await fireEvent.input(screen.getByLabelText(/verification code/i), { target: { value: '123456' } })
      await fireEvent.click(screen.getByRole('button', { name: /confirm email change/i }))
      await waitFor(() => {
        expect(screen.getByText(/email updated successfully/i)).toBeInTheDocument()
      })
    })
    it('shows cancel button to return to email form', async () => {
      mockEndpoint('com.atproto.server.requestEmailUpdate', () =>
        jsonResponse({ tokenRequired: true })
      )
      render(Settings)
      await waitFor(() => {
        expect(screen.getByLabelText(/new email/i)).toBeInTheDocument()
      })
      await fireEvent.input(screen.getByLabelText(/new email/i), { target: { value: 'new@test.com' } })
      await fireEvent.click(screen.getByRole('button', { name: /change email/i }))
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument()
      })
      await fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
      await waitFor(() => {
        expect(screen.getByLabelText(/new email/i)).toBeInTheDocument()
        expect(screen.queryByLabelText(/verification code/i)).not.toBeInTheDocument()
      })
    })
    it('shows error when email update fails', async () => {
      mockEndpoint('com.atproto.server.requestEmailUpdate', () =>
        errorResponse('InvalidEmail', 'Invalid email format', 400)
      )
      render(Settings)
      await waitFor(() => {
        expect(screen.getByLabelText(/new email/i)).toBeInTheDocument()
      })
      await fireEvent.input(screen.getByLabelText(/new email/i), { target: { value: 'invalid@test.com' } })
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /change email/i })).not.toBeDisabled()
      })
      await fireEvent.click(screen.getByRole('button', { name: /change email/i }))
      await waitFor(() => {
        expect(screen.getByText(/invalid email format/i)).toBeInTheDocument()
      })
    })
  })
  describe('handle change', () => {
    beforeEach(() => {
      setupAuthenticatedUser()
    })
    it('displays current handle', async () => {
      render(Settings)
      await waitFor(() => {
        expect(screen.getByText(/current: @testuser\.test\.tranquil\.dev/i)).toBeInTheDocument()
      })
    })
    it('calls updateHandle with new handle', async () => {
      let capturedHandle: string | null = null
      mockEndpoint('com.atproto.identity.updateHandle', (_url, options) => {
        const body = JSON.parse((options?.body as string) || '{}')
        capturedHandle = body.handle
        return jsonResponse({})
      })
      render(Settings)
      await waitFor(() => {
        expect(screen.getByLabelText(/new handle/i)).toBeInTheDocument()
      })
      await fireEvent.input(screen.getByLabelText(/new handle/i), { target: { value: 'newhandle.bsky.social' } })
      await fireEvent.click(screen.getByRole('button', { name: /change handle/i }))
      await waitFor(() => {
        expect(capturedHandle).toBe('newhandle.bsky.social')
      })
    })
    it('shows success message after handle change', async () => {
      mockEndpoint('com.atproto.identity.updateHandle', () =>
        jsonResponse({})
      )
      render(Settings)
      await waitFor(() => {
        expect(screen.getByLabelText(/new handle/i)).toBeInTheDocument()
      })
      await fireEvent.input(screen.getByLabelText(/new handle/i), { target: { value: 'newhandle' } })
      await fireEvent.click(screen.getByRole('button', { name: /change handle/i }))
      await waitFor(() => {
        expect(screen.getByText(/handle updated successfully/i)).toBeInTheDocument()
      })
    })
    it('shows error when handle change fails', async () => {
      mockEndpoint('com.atproto.identity.updateHandle', () =>
        errorResponse('HandleNotAvailable', 'Handle is already taken', 400)
      )
      render(Settings)
      await waitFor(() => {
        expect(screen.getByLabelText(/new handle/i)).toBeInTheDocument()
      })
      await fireEvent.input(screen.getByLabelText(/new handle/i), { target: { value: 'taken' } })
      await fireEvent.click(screen.getByRole('button', { name: /change handle/i }))
      await waitFor(() => {
        expect(screen.getByText(/handle is already taken/i)).toBeInTheDocument()
      })
    })
  })
  describe('account deletion', () => {
    beforeEach(() => {
      setupAuthenticatedUser()
      mockEndpoint('com.atproto.server.deleteSession', () =>
        jsonResponse({})
      )
    })
    it('displays delete section with warning and request button', async () => {
      render(Settings)
      await waitFor(() => {
        expect(screen.getByText(/this action is irreversible/i)).toBeInTheDocument()
        expect(screen.getByRole('button', { name: /request account deletion/i })).toBeInTheDocument()
      })
    })
    it('calls requestAccountDelete when clicking request', async () => {
      let requestCalled = false
      mockEndpoint('com.atproto.server.requestAccountDelete', () => {
        requestCalled = true
        return jsonResponse({})
      })
      render(Settings)
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /request account deletion/i })).toBeInTheDocument()
      })
      await fireEvent.click(screen.getByRole('button', { name: /request account deletion/i }))
      await waitFor(() => {
        expect(requestCalled).toBe(true)
      })
    })
    it('shows confirmation form after requesting deletion', async () => {
      mockEndpoint('com.atproto.server.requestAccountDelete', () =>
        jsonResponse({})
      )
      render(Settings)
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /request account deletion/i })).toBeInTheDocument()
      })
      await fireEvent.click(screen.getByRole('button', { name: /request account deletion/i }))
      await waitFor(() => {
        expect(screen.getByLabelText(/confirmation code/i)).toBeInTheDocument()
        expect(screen.getByLabelText(/your password/i)).toBeInTheDocument()
        expect(screen.getByRole('button', { name: /permanently delete account/i })).toBeInTheDocument()
      })
    })
    it('shows confirmation dialog before final deletion', async () => {
      const confirmSpy = vi.fn(() => false)
      window.confirm = confirmSpy
      mockEndpoint('com.atproto.server.requestAccountDelete', () =>
        jsonResponse({})
      )
      render(Settings)
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /request account deletion/i })).toBeInTheDocument()
      })
      await fireEvent.click(screen.getByRole('button', { name: /request account deletion/i }))
      await waitFor(() => {
        expect(screen.getByLabelText(/confirmation code/i)).toBeInTheDocument()
      })
      await fireEvent.input(screen.getByLabelText(/confirmation code/i), { target: { value: 'ABC123' } })
      await fireEvent.input(screen.getByLabelText(/your password/i), { target: { value: 'password' } })
      await fireEvent.click(screen.getByRole('button', { name: /permanently delete account/i }))
      expect(confirmSpy).toHaveBeenCalledWith(
        expect.stringContaining('absolutely sure')
      )
    })
    it('calls deleteAccount with correct parameters', async () => {
      window.confirm = vi.fn(() => true)
      let capturedBody: Record<string, string> | null = null
      mockEndpoint('com.atproto.server.requestAccountDelete', () =>
        jsonResponse({})
      )
      mockEndpoint('com.atproto.server.deleteAccount', (_url, options) => {
        capturedBody = JSON.parse((options?.body as string) || '{}')
        return jsonResponse({})
      })
      render(Settings)
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /request account deletion/i })).toBeInTheDocument()
      })
      await fireEvent.click(screen.getByRole('button', { name: /request account deletion/i }))
      await waitFor(() => {
        expect(screen.getByLabelText(/confirmation code/i)).toBeInTheDocument()
      })
      await fireEvent.input(screen.getByLabelText(/confirmation code/i), { target: { value: 'DEL123' } })
      await fireEvent.input(screen.getByLabelText(/your password/i), { target: { value: 'mypassword' } })
      await fireEvent.click(screen.getByRole('button', { name: /permanently delete account/i }))
      await waitFor(() => {
        expect(capturedBody?.token).toBe('DEL123')
        expect(capturedBody?.password).toBe('mypassword')
        expect(capturedBody?.did).toBe('did:web:test.tranquil.dev:u:testuser')
      })
    })
    it('navigates to login after successful deletion', async () => {
      window.confirm = vi.fn(() => true)
      mockEndpoint('com.atproto.server.requestAccountDelete', () =>
        jsonResponse({})
      )
      mockEndpoint('com.atproto.server.deleteAccount', () =>
        jsonResponse({})
      )
      render(Settings)
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /request account deletion/i })).toBeInTheDocument()
      })
      await fireEvent.click(screen.getByRole('button', { name: /request account deletion/i }))
      await waitFor(() => {
        expect(screen.getByLabelText(/confirmation code/i)).toBeInTheDocument()
      })
      await fireEvent.input(screen.getByLabelText(/confirmation code/i), { target: { value: 'DEL123' } })
      await fireEvent.input(screen.getByLabelText(/your password/i), { target: { value: 'password' } })
      await fireEvent.click(screen.getByRole('button', { name: /permanently delete account/i }))
      await waitFor(() => {
        expect(window.location.hash).toBe('#/login')
      })
    })
    it('shows cancel button to return to request state', async () => {
      mockEndpoint('com.atproto.server.requestAccountDelete', () =>
        jsonResponse({})
      )
      render(Settings)
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /request account deletion/i })).toBeInTheDocument()
      })
      await fireEvent.click(screen.getByRole('button', { name: /request account deletion/i }))
      await waitFor(() => {
        const cancelButtons = screen.getAllByRole('button', { name: /cancel/i })
        expect(cancelButtons.length).toBeGreaterThan(0)
      })
      const deleteHeading = screen.getByRole('heading', { name: /delete account/i })
      const deleteSection = deleteHeading.closest('section')
      const cancelButton = deleteSection?.querySelector('button.secondary')
      if (cancelButton) {
        await fireEvent.click(cancelButton)
      }
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /request account deletion/i })).toBeInTheDocument()
      })
    })
    it('shows error when deletion fails', async () => {
      window.confirm = vi.fn(() => true)
      mockEndpoint('com.atproto.server.requestAccountDelete', () =>
        jsonResponse({})
      )
      mockEndpoint('com.atproto.server.deleteAccount', () =>
        errorResponse('InvalidToken', 'Invalid confirmation code', 400)
      )
      render(Settings)
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /request account deletion/i })).toBeInTheDocument()
      })
      await fireEvent.click(screen.getByRole('button', { name: /request account deletion/i }))
      await waitFor(() => {
        expect(screen.getByLabelText(/confirmation code/i)).toBeInTheDocument()
      })
      await fireEvent.input(screen.getByLabelText(/confirmation code/i), { target: { value: 'WRONG' } })
      await fireEvent.input(screen.getByLabelText(/your password/i), { target: { value: 'password' } })
      await fireEvent.click(screen.getByRole('button', { name: /permanently delete account/i }))
      await waitFor(() => {
        expect(screen.getByText(/invalid confirmation code/i)).toBeInTheDocument()
      })
    })
  })
})
