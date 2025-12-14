import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte'
import Dashboard from '../routes/Dashboard.svelte'
import {
  setupFetchMock,
  mockEndpoint,
  jsonResponse,
  mockData,
  clearMocks,
  setupAuthenticatedUser,
  setupUnauthenticatedUser,
} from './mocks'
const STORAGE_KEY = 'bspds_session'
describe('Dashboard', () => {
  beforeEach(() => {
    clearMocks()
    setupFetchMock()
  })
  describe('authentication guard', () => {
    it('redirects to login when not authenticated', async () => {
      setupUnauthenticatedUser()
      render(Dashboard)
      await waitFor(() => {
        expect(window.location.hash).toBe('#/login')
      })
    })
    it('shows loading state while checking auth', () => {
      render(Dashboard)
      expect(screen.getByText(/loading/i)).toBeInTheDocument()
    })
  })
  describe('authenticated view', () => {
    beforeEach(() => {
      setupAuthenticatedUser()
    })
    it('displays user account info and page structure', async () => {
      render(Dashboard)
      await waitFor(() => {
        expect(screen.getByRole('heading', { name: /dashboard/i })).toBeInTheDocument()
        expect(screen.getByRole('heading', { name: /account overview/i })).toBeInTheDocument()
        expect(screen.getByText(/@testuser\.test\.bspds\.dev/)).toBeInTheDocument()
        expect(screen.getByText(/did:web:test\.bspds\.dev:u:testuser/)).toBeInTheDocument()
        expect(screen.getByText('test@example.com')).toBeInTheDocument()
        expect(screen.getByText('Verified')).toBeInTheDocument()
        expect(screen.getByText('Verified')).toHaveClass('badge', 'success')
      })
    })
    it('displays unverified badge when email not confirmed', async () => {
      setupAuthenticatedUser({ emailConfirmed: false })
      render(Dashboard)
      await waitFor(() => {
        expect(screen.getByText('Unverified')).toBeInTheDocument()
        expect(screen.getByText('Unverified')).toHaveClass('badge', 'warning')
      })
    })
    it('displays all navigation cards', async () => {
      render(Dashboard)
      await waitFor(() => {
        const navCards = [
          { name: /app passwords/i, href: '#/app-passwords' },
          { name: /invite codes/i, href: '#/invite-codes' },
          { name: /account settings/i, href: '#/settings' },
          { name: /notification preferences/i, href: '#/notifications' },
          { name: /repository explorer/i, href: '#/repo' },
        ]
        for (const { name, href } of navCards) {
          const card = screen.getByRole('link', { name })
          expect(card).toBeInTheDocument()
          expect(card).toHaveAttribute('href', href)
        }
      })
    })
  })
  describe('logout functionality', () => {
    beforeEach(() => {
      setupAuthenticatedUser()
      localStorage.setItem(STORAGE_KEY, JSON.stringify(mockData.session()))
      mockEndpoint('com.atproto.server.deleteSession', () =>
        jsonResponse({})
      )
    })
    it('calls deleteSession and navigates to login on logout', async () => {
      let deleteSessionCalled = false
      mockEndpoint('com.atproto.server.deleteSession', () => {
        deleteSessionCalled = true
        return jsonResponse({})
      })
      render(Dashboard)
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /sign out/i })).toBeInTheDocument()
      })
      await fireEvent.click(screen.getByRole('button', { name: /sign out/i }))
      await waitFor(() => {
        expect(deleteSessionCalled).toBe(true)
        expect(window.location.hash).toBe('#/login')
      })
    })
    it('clears session from localStorage after logout', async () => {
      const storedSession = localStorage.getItem(STORAGE_KEY)
      expect(storedSession).not.toBeNull()
      render(Dashboard)
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /sign out/i })).toBeInTheDocument()
      })
      await fireEvent.click(screen.getByRole('button', { name: /sign out/i }))
      await waitFor(() => {
        expect(localStorage.getItem(STORAGE_KEY)).toBeNull()
      })
    })
  })
})
