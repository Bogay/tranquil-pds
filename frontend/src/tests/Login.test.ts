import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte'
import Login from '../routes/Login.svelte'
import {
  setupFetchMock,
  mockEndpoint,
  jsonResponse,
  errorResponse,
  mockData,
  clearMocks,
} from './mocks'
describe('Login', () => {
  beforeEach(() => {
    clearMocks()
    setupFetchMock()
    window.location.hash = ''
  })
  describe('initial render', () => {
    it('renders login form with all elements and correct initial state', () => {
      render(Login)
      expect(screen.getByRole('heading', { name: /sign in/i })).toBeInTheDocument()
      expect(screen.getByLabelText(/handle or email/i)).toBeInTheDocument()
      expect(screen.getByLabelText(/password/i)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /sign in/i })).toBeDisabled()
      expect(screen.getByText(/don't have an account/i)).toBeInTheDocument()
      expect(screen.getByRole('link', { name: /create one/i })).toHaveAttribute('href', '#/register')
    })
  })
  describe('form validation', () => {
    it('enables submit button only when both fields are filled', async () => {
      render(Login)
      const identifierInput = screen.getByLabelText(/handle or email/i)
      const passwordInput = screen.getByLabelText(/password/i)
      const submitButton = screen.getByRole('button', { name: /sign in/i })
      await fireEvent.input(identifierInput, { target: { value: 'testuser' } })
      expect(submitButton).toBeDisabled()
      await fireEvent.input(identifierInput, { target: { value: '' } })
      await fireEvent.input(passwordInput, { target: { value: 'password123' } })
      expect(submitButton).toBeDisabled()
      await fireEvent.input(identifierInput, { target: { value: 'testuser' } })
      expect(submitButton).not.toBeDisabled()
    })
  })
  describe('login submission', () => {
    it('calls createSession with correct credentials', async () => {
      let capturedBody: Record<string, string> | null = null
      mockEndpoint('com.atproto.server.createSession', (_url, options) => {
        capturedBody = JSON.parse((options?.body as string) || '{}')
        return jsonResponse(mockData.session())
      })
      render(Login)
      await fireEvent.input(screen.getByLabelText(/handle or email/i), { target: { value: 'testuser@example.com' } })
      await fireEvent.input(screen.getByLabelText(/password/i), { target: { value: 'mypassword' } })
      await fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
      await waitFor(() => {
        expect(capturedBody).toEqual({
          identifier: 'testuser@example.com',
          password: 'mypassword',
        })
      })
    })
    it('shows styled error message on invalid credentials', async () => {
      mockEndpoint('com.atproto.server.createSession', () =>
        errorResponse('AuthenticationRequired', 'Invalid identifier or password', 401)
      )
      render(Login)
      await fireEvent.input(screen.getByLabelText(/handle or email/i), { target: { value: 'wronguser' } })
      await fireEvent.input(screen.getByLabelText(/password/i), { target: { value: 'wrongpassword' } })
      await fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
      await waitFor(() => {
        const errorDiv = screen.getByText(/invalid identifier or password/i)
        expect(errorDiv).toBeInTheDocument()
        expect(errorDiv).toHaveClass('error')
      })
    })
    it('navigates to dashboard on successful login', async () => {
      mockEndpoint('com.atproto.server.createSession', () =>
        jsonResponse(mockData.session())
      )
      render(Login)
      await fireEvent.input(screen.getByLabelText(/handle or email/i), { target: { value: 'test' } })
      await fireEvent.input(screen.getByLabelText(/password/i), { target: { value: 'password' } })
      await fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
      await waitFor(() => {
        expect(window.location.hash).toBe('#/dashboard')
      })
    })
  })
  describe('account verification flow', () => {
    it('shows verification form with all controls when account is not verified', async () => {
      mockEndpoint('com.atproto.server.createSession', () => ({
        ok: false,
        status: 401,
        json: async () => ({
          error: 'AccountNotVerified',
          message: 'Account not verified',
          did: 'did:web:test.bspds.dev:u:testuser',
        }),
      }))
      render(Login)
      await fireEvent.input(screen.getByLabelText(/handle or email/i), { target: { value: 'unverified@test.com' } })
      await fireEvent.input(screen.getByLabelText(/password/i), { target: { value: 'password' } })
      await fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
      await waitFor(() => {
        expect(screen.getByRole('heading', { name: /verify your account/i })).toBeInTheDocument()
        expect(screen.getByLabelText(/verification code/i)).toBeInTheDocument()
        expect(screen.getByRole('button', { name: /resend code/i })).toBeInTheDocument()
        expect(screen.getByRole('button', { name: /back to login/i })).toBeInTheDocument()
      })
    })
    it('returns to login form when clicking back', async () => {
      mockEndpoint('com.atproto.server.createSession', () => ({
        ok: false,
        status: 401,
        json: async () => ({
          error: 'AccountNotVerified',
          message: 'Account not verified',
          did: 'did:web:test.bspds.dev:u:testuser',
        }),
      }))
      render(Login)
      await fireEvent.input(screen.getByLabelText(/handle or email/i), { target: { value: 'test' } })
      await fireEvent.input(screen.getByLabelText(/password/i), { target: { value: 'password' } })
      await fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /back to login/i })).toBeInTheDocument()
      })
      await fireEvent.click(screen.getByRole('button', { name: /back to login/i }))
      await waitFor(() => {
        expect(screen.getByRole('heading', { name: /sign in/i })).toBeInTheDocument()
        expect(screen.queryByLabelText(/verification code/i)).not.toBeInTheDocument()
      })
    })
  })
})
