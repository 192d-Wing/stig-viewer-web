import Button from '@cloudscape-design/components/button'
import Box from '@cloudscape-design/components/box'
import SpaceBetween from '@cloudscape-design/components/space-between'
import Container from '@cloudscape-design/components/container'
import Header from '@cloudscape-design/components/header'
import { redirectToLogin } from '../api.js'

export default function Login() {
  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 24,
      }}
    >
      <div style={{ maxWidth: 480, width: '100%' }}>
        <Container
          header={
            <Header
              variant="h1"
              description="Sign in with your identity provider to continue."
            >
              STIG Viewer
            </Header>
          }
        >
          <SpaceBetween size="l">
            <Box variant="p" color="text-body-secondary">
              This instance requires authentication. You will be redirected to
              your organization&rsquo;s identity provider, then returned here.
            </Box>
            <Button variant="primary" onClick={() => redirectToLogin()}>
              Log in with identity provider
            </Button>
          </SpaceBetween>
        </Container>
      </div>
    </div>
  )
}
