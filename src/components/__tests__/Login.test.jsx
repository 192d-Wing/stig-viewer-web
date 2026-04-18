import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import Login from '../Login.jsx'

describe('<Login />', () => {
  const originalLocation = window.location

  beforeEach(() => {
    // jsdom's window.location is read-only; replace with a writeable stub so
    // we can observe redirects.
    delete window.location
    window.location = { href: 'http://localhost:5173/' }
  })
  afterEach(() => {
    window.location = originalLocation
    vi.restoreAllMocks()
  })

  it('renders the sign-in heading and button', () => {
    render(<Login />)
    expect(screen.getByText('STIG Viewer')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /log in with identity provider/i }),
    ).toBeInTheDocument()
  })

  it('redirects to the backend login endpoint when clicked', () => {
    render(<Login />)
    fireEvent.click(
      screen.getByRole('button', { name: /log in with identity provider/i }),
    )
    expect(window.location.href).toMatch(/\/api\/auth\/login\?return_to=/)
    // return_to is URL-encoded and preserves the starting page
    expect(decodeURIComponent(window.location.href)).toContain(
      'return_to=http://localhost:5173/',
    )
  })
})
