/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"os"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	dbuser "github.com/hyperledger/fabric-ca/lib/server/user"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
	"encoding/pem"
		"github.com/tjfoc/gmsm/sm2"
)

func TestStateUpdate(t *testing.T) {
	cleanTestSlateSE(t)
	defer cleanTestSlateSE(t)

	var err error
	srv := TestGetRootServer(t)

	err = srv.Start()
	assert.NoError(t, err, "Failed to start server")

	client := getTestClient(rootPort)
	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	assert.NoError(t, err, "Failed to enroll 'admin' user")

	registry := srv.CA.DBAccessor()
	userInfo, err := registry.GetUser("admin", nil)
	assert.NoError(t, err, "Failed to get user 'admin' from database")
	// User state should have gotten updated to 1 after a successful enrollment
	if userInfo.(*dbuser.Impl).State != 1 {
		t.Error("Incorrect state set for user")
	}

	// Send bad CSR to cause the enroll to fail but the login to succeed
	reqNet := &api.EnrollmentRequestNet{}
	reqNet.SignRequest.Request = "badcsr"
	body, err := util.Marshal(reqNet, "SignRequest")
	assert.NoError(t, err, "Failed to marshal enroll request")

	// Send the CSR to the fabric-ca server with basic auth header
	post, err := client.newPost("enroll", body)
	assert.NoError(t, err, "Failed to create post request")
	post.SetBasicAuth("admin", "adminpw")
	err = client.SendReq(post, nil)
	if assert.Error(t, err, "Should have failed due to bad csr") {
		assert.Contains(t, err.Error(), "CSR Decode failed")
	}

	// State should not have gotten updated because the enrollment failed
	userInfo, err = registry.GetUser("admin", nil)
	assert.NoError(t, err, "Failed to get user 'admin' from database")
	if userInfo.(*dbuser.Impl).State != 1 {
		t.Error("Incorrect state set for user")
	}

	err = srv.Stop()
	assert.NoError(t, err, "Failed to stop server")

}

func cleanTestSlateSE(t *testing.T) {
	err := os.RemoveAll(rootDir)
	if err != nil {
		t.Errorf("RemoveAll failed: %s", err)
	}
	err = os.RemoveAll("../testdata/msp")
	if err != nil {
		t.Errorf("RemoveAll failed: %s", err)
	}
}

func TestPasswordLimit(t *testing.T) {
	cleanTestSlateSE(t)
	defer cleanTestSlateSE(t)

	passLimit := 3

	srv := TestGetRootServer(t)
	srv.CA.Config.Cfg.Identities.PasswordAttempts = passLimit
	err := srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()

	client := getTestClient(rootPort)
	enrollResp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll 'admin' user")
	admin := enrollResp.Identity

	_, err = admin.Register(&api.RegistrationRequest{
		Name:   "user1",
		Secret: "user1pw",
	})
	util.FatalError(t, err, "Failed to register 'user1' user")

	// Reach maximum incorrect password limit
	for i := 0; i < passLimit; i++ {
		_, err = client.Enroll(&api.EnrollmentRequest{
			Name:   "user1",
			Secret: "badpass",
		})
		assert.Error(t, err, "Enroll for user 'user1' should fail due to bad password")
	}
	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "user1",
		Secret: "badpass",
	})
	util.ErrorContains(t, err, "73", "Should fail, incorrect password limit reached")

	// Admin modifying identity, confirm that just modifying identity does not reset attempt
	// count. Incorrect password attempt count should only be reset to zero, if password
	// is modified.
	modReq := &api.ModifyIdentityRequest{
		ID: "user1",
	}

	modReq.Type = "client"
	_, err = admin.ModifyIdentity(modReq)
	assert.NoError(t, err, "Failed to modify identity")

	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "user1",
		Secret: "user1pw",
	})
	assert.Error(t, err, "Should failed to enroll")

	// Admin reset password
	modReq.Secret = "newPass"
	_, err = admin.ModifyIdentity(modReq)
	assert.NoError(t, err, "Failed to modify identity")

	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "user1",
		Secret: "newPass",
	})
	assert.NoError(t, err, "Failed to enroll using new password after admin reset password")

	// Test that if password is entered correctly before reaching incorrect password limit,
	// the incorrect password count is reset back to 0
	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "user1",
		Secret: "badPass",
	})
	assert.Error(t, err, "Enroll for user 'user1' should fail due to bad password")

	registry := srv.CA.DBAccessor()
	user1, err := registry.GetUser("user1", nil)
	util.FatalError(t, err, "Failed to get 'user1' from database")
	assert.Equal(t, 1, user1.GetFailedLoginAttempts())

	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "user1",
		Secret: "newPass",
	})
	assert.NoError(t, err, "Failed to enroll user with correct password")

	user1, err = registry.GetUser("user1", nil)
	util.FatalError(t, err, "Failed to get 'user1' from database")
	assert.Equal(t, 0, user1.GetFailedLoginAttempts())
}

func TestParse(t *testing.T) {
	block, _ := pem.Decode([]byte("-----BEGIN CERTIFICATE REQUEST-----\nMIIBQzCB6QIBADBdMQswCQYDVQQGEwJVUzEXMBUGA1UECBMOTm9ydGggQ2Fyb2xp\nbmExFDASBgNVBAoTC0h5cGVybGVkZ2VyMQ8wDQYDVQQLEwZGYWJyaWMxDjAMBgNV\nBAMTBWFkbWluMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEqkk8Dimw5/jTRO0T\nu6YDkWcVK0Zo0ic5DCxPWkzLB7KBXPoAdWRpTuA6O13dk7xZT3cEIVHTCDAn8EEO\noQvmOqAqMCgGCSqGSIb3DQEJDjEbMBkwFwYDVR0RBBAwDoIMd2FsbGV0LXJkLTYz\nMAoGCCqBHM9VAYN1A0kAMEYCIQDrFKbR7I09fhJmuBuUys0kewd6jplS6u8qRKtb\n3dwNpgIhAIOCH/wU6+A0B6cUbsNb/y2O/mLZMcGGdbFaWAAejQDO\n-----END CERTIFICATE REQUEST-----"));
	var err error
	_, err = sm2.ParseCertificateRequest(block.Bytes)
	assert.Equal(t, nil, err)
	//err = SignCertSm2("-----BEGIN CERTIFICATE REQUEST-----\nMIIBBTCBrQIBADAQMQ4wDAYDVQQDEwVhZG1pbjBZMBMGByqGSM49AgEGCCqBHM9V\nAYItA0IABKfD6fMfJbGiFV9/aLc2OVW/qcOFBcWX3TOO3SvRWgXp21/cMlJgI/1O\nnDgGPmCR2+aJqlkm32d0IS0khrHuqvOgOzA5BgkqhkiG9w0BCQ4xLDAqMCgGA1Ud\nEQQhMB+CHWRhaXF1bmJpYW9kZU1hY0Jvb2stUHJvLmxvY2FsMAoGCCqBHM9VAYN1\nA0cAMEQCIA2X8PBFzjyb8BxDEw0mpJvJSvavQdN8Dvsr1vNKGvzDAiAoqJePneGh\nxW3C4rWm6jxhXVZ9jkxlrnp0/2GACBKcMA==\n-----END CERTIFICATE REQUEST-----")
	//err = SignCertSm2("-----BEGIN CERTIFICATE REQUEST-----\nMIIBBjCBrQIBADAQMQ4wDAYDVQQDEwVhZG1pbjBZMBMGByqGSM49AgEGCCqBHM9V\nAYItA0IABNf3OY/sfv3zsBFcdnGnncPHVZbiXDunpHzHJfyyxNQ5G3Wdap9hFtSP\nx9ym2ogJZGtaQG5Alr4+lNAkuky24fegOzA5BgkqhkiG9w0BCQ4xLDAqMCgGA1Ud\nEQQhMB+CHWRhaXF1bmJpYW9kZU1hY0Jvb2stUHJvLmxvY2FsMAoGCCqBHM9VAYN1\nA0gAMEUCIBIF4uYCCYa8+mIYkBmPl0Td0dTcw6UB7LneOevo5xWyAiEAwPr62OOE\nb2OHrXT4QJ2CGct5miE5THFeZ5a8N9yW5gY=\n-----END CERTIFICATE REQUEST-----\n")
	err = SignCertSm2("-----BEGIN CERTIFICATE REQUEST-----\nMIIBQzCB6QIBADBdMQswCQYDVQQGEwJVUzEXMBUGA1UECBMOTm9ydGggQ2Fyb2xp\nbmExFDASBgNVBAoTC0h5cGVybGVkZ2VyMQ8wDQYDVQQLEwZGYWJyaWMxDjAMBgNV\nBAMTBWFkbWluMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEqkk8Dimw5/jTRO0T\nu6YDkWcVK0Zo0ic5DCxPWkzLB7KBXPoAdWRpTuA6O13dk7xZT3cEIVHTCDAn8EEO\noQvmOqAqMCgGCSqGSIb3DQEJDjEbMBkwFwYDVR0RBBAwDoIMd2FsbGV0LXJkLTYz\nMAoGCCqBHM9VAYN1A0kAMEYCIQDrFKbR7I09fhJmuBuUys0kewd6jplS6u8qRKtb\n3dwNpgIhAIOCH/wU6+A0B6cUbsNb/y2O/mLZMcGGdbFaWAAejQDO\n-----END CERTIFICATE REQUEST-----")
	//err = SignCertSm2("-----BEGIN CERTIFICATE REQUEST-----\nMIIBODCB4AIBADBcMQswCQYDVQQGEwJVUzEXMBUGA1UECBMOTm9ydGggQ2Fyb2xp\nbmExFDASBgNVBAoTC0h5cGVybGVkZ2VyMQ8wDQYDVQQLEwZGYWJyaWMxDTALBgNV\nBAMTBHVzZXIwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATDtmSCmutJC1An3a2/\nP3El0GHVc5cXSD/IFpsArj0ErA6o924/4nkE02I09eTaXeLIsYvHO6ybuKb6wY9S\nbYYNoCIwIAYJKoZIhvcNAQkOMRMwETAPBgNVHREECDAGhwTAqAJkMAoGCCqBHM9V\nAYN1A0cAMEQCIBUiILjiYKEzuRLBxk73XLBRm7GzP7aV93Lq/6jsDtNPAiBlNoJN\nE3Ywesn+T2DLZCYd4mbIoU/RnhrHwdinrmcRzw==\n-----END CERTIFICATE REQUEST-----\n")
	assert.Equal(t, nil, err)
}

//"-----BEGIN CERTIFICATE REQUEST-----\nMIH3MIGfAgEAMA0xCzAJBgNVBAMTAnV1MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\nQgAE4rZnYuB0Wlz81dqIC5xxZBbLWKWZAXucPDam6RTta6GGxtdmA5O8+1sdVAsT\n2Fd4267Q8mGk0z4IMxeIUsJ7VaAwMC4GCSqGSIb3DQEJDjEhMB8wHQYDVR0RBBYw\nFIISQzAyV1Q1U1hHOFdOLmxvY2FsMAoGCCqGSM49BAMCA0cAMEQCIBTedq7/K/Bc\nVHhFBfKX7jp1soIJveDbz9ThP1fLPpl9AiBOfj4gQeT1H2o3XF6mwweZSV9cKif2\nuOMiOuHPjaRP2g==\n-----END CERTIFICATE REQUEST-----\n"
//"-----BEGIN CERTIFICATE REQUEST-----\nMIIBQzCB6QIBADBdMQswCQYDVQQGEwJVUzEXMBUGA1UECBMOTm9ydGggQ2Fyb2xp\nbmExFDASBgNVBAoTC0h5cGVybGVkZ2VyMQ8wDQYDVQQLEwZGYWJyaWMxDjAMBgNV\nBAMTBWFkbWluMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEqkk8Dimw5/jTRO0T\nu6YDkWcVK0Zo0ic5DCxPWkzLB7KBXPoAdWRpTuA6O13dk7xZT3cEIVHTCDAn8EEO\noQvmOqAqMCgGCSqGSIb3DQEJDjEbMBkwFwYDVR0RBBAwDoIMd2FsbGV0LXJkLTYz\nMAoGCCqBHM9VAYN1A0kAMEYCIQDrFKbR7I09fhJmuBuUys0kewd6jplS6u8qRKtb\n3dwNpgIhAIOCH/wU6+A0B6cUbsNb/y2O/mLZMcGGdbFaWAAejQDO\n-----END CERTIFICATE REQUEST-----"


//"-----BEGIN CERTIFICATE REQUEST-----\nMIIBODCB4AIBADBcMQswCQYDVQQGEwJVUzEXMBUGA1UECBMOTm9ydGggQ2Fyb2xp\nbmExFDASBgNVBAoTC0h5cGVybGVkZ2VyMQ8wDQYDVQQLEwZGYWJyaWMxDTALBgNV\nBAMTBHVzZXIwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATDtmSCmutJC1An3a2/\nP3El0GHVc5cXSD/IFpsArj0ErA6o924/4nkE02I09eTaXeLIsYvHO6ybuKb6wY9S\nbYYNoCIwIAYJKoZIhvcNAQkOMRMwETAPBgNVHREECDAGhwTAqAJkMAoGCCqBHM9V\nAYN1A0cAMEQCIBUiILjiYKEzuRLBxk73XLBRm7GzP7aV93Lq/6jsDtNPAiBlNoJN\nE3Ywesn+T2DLZCYd4mbIoU/RnhrHwdinrmcRzw==\n-----END CERTIFICATE REQUEST-----\n"
//"-----BEGIN CERTIFICATE REQUEST-----\nMIIBBTCBrQIBADAQMQ4wDAYDVQQDEwVhZG1pbjBZMBMGByqGSM49AgEGCCqBHM9V\nAYItA0IABKfD6fMfJbGiFV9/aLc2OVW/qcOFBcWX3TOO3SvRWgXp21/cMlJgI/1O\nnDgGPmCR2+aJqlkm32d0IS0khrHuqvOgOzA5BgkqhkiG9w0BCQ4xLDAqMCgGA1Ud\nEQQhMB+CHWRhaXF1bmJpYW9kZU1hY0Jvb2stUHJvLmxvY2FsMAoGCCqBHM9VAYN1\nA0cAMEQCIA2X8PBFzjyb8BxDEw0mpJvJSvavQdN8Dvsr1vNKGvzDAiAoqJePneGh\nxW3C4rWm6jxhXVZ9jkxlrnp0/2GACBKcMA==\n-----END CERTIFICATE REQUEST-----"