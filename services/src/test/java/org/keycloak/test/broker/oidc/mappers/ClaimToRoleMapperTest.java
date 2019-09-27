/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.test.broker.oidc.mappers;

//import com.fasterxml.jackson.core.JsonProcessingException;
//import com.fasterxml.jackson.databind.JsonNode;
//import com.fasterxml.jackson.databind.ObjectMapper;
//import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;

import java.io.IOException;
import java.util.Map;
import java.util.HashMap;

import org.keycloak.models.RoleModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.broker.oidc.mappers.ClaimToRoleMapper;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.ConfigConstants;
import org.keycloak.broker.oidc.KeycloakOIDCIdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractClaimMapper;

import static org.mockito.Mockito.*;

import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.is;

import org.junit.Test;


/**
 * Unit test for {@link org.keycloak.broker.oidc.mappers.ClaimToRoleMapper}
 *
 * @author Frederic BIDON
 */
public class ClaimToRoleMapperTest extends AbstractRoleMapperTest {
    
    private IdentityProviderMapperModel getMapperModel(String testcase){
    	IdentityProviderMapperModel mapperModel = new IdentityProviderMapperModel();
    	mapperModel.setId(ClaimToRoleMapper.PROVIDER_ID);
    	mapperModel.setName("test mapper");
    	
    	Map<String,String> config = new HashMap<>();
    	config.put(ClaimToRoleMapper.CLAIM,"claim");
    	config.put(ClaimToRoleMapper.CLAIM_VALUE,testcase);
    	config.put(ConfigConstants.ROLE,"role:"+testcase);
    	mapperModel.setConfig(config);
        return mapperModel;
    }
    
    private BrokeredIdentityContext makeMockContext(String claim) {
    	// build token with claim in mocked context
        when(mockContext.getContextData()).thenAnswer(new Answer<Map<String,Object>>() {
        	@Override
            public Map<String, Object> answer(InvocationOnMock invocation) throws Throwable {
        		Map<String,Object> data = new HashMap<>();
        		JsonWebToken token = new JsonWebToken();
        		token.setOtherClaims("claim", claim);
        		data.put(KeycloakOIDCIdentityProvider.VALIDATED_ACCESS_TOKEN, token);
        		return data;
        	}
        });
        return mockContext;
    }
    
    @Test
	public void sanityMapperTest() throws IOException {
		initMocks();

		IdentityProviderMapperModel mapperModel = getMapperModel("can-do-this"); 

        // 0. sanity check
        Object value = AbstractClaimMapper.getClaimValue(makeMockContext("no-can-do"), "claim");
        assertThat(value,is("no-can-do")); 	
    }
    
	@Test
	public void importNewUserTest() throws IOException {
		initMocks();

		IdentityProviderMapperModel mapperModel = getMapperModel("can-do-this"); 

        ClaimToRoleMapper mapper  = new ClaimToRoleMapper();
		
        mapper.create(mockSession);
        
        // 1. create new user 1 without "claim" claim mapped to role: assert user does not have role
        BrokeredIdentityContext context = makeMockContext("no-can-do");
        mapper.importNewUser(mockSession, mockRealm, mockUser1, mapperModel, context);
        
        verify(mockUser1, never()).grantRole(any(RoleModel.class));
        verify(mockUser1, never()).deleteRoleMapping(any(RoleModel.class));
        verify(mockRealm, never()).getRole(anyString());

        // 2. create new user 2 with "claim" claim mapped to role
        context = makeMockContext("can-do-this");
        mapper.importNewUser(mockSession, mockRealm, mockUser2, mapperModel, context);
        
        verify(mockUser2, times(1)).grantRole(grantedArg.capture());
        verify(mockUser2, never()).deleteRoleMapping(any(RoleModel.class));
        verify(mockRealm, atLeastOnce()).getRole(roleArg.capture());
        
        assertThat(grantedArg.getValue().getName(), is("role:can-do-this"));
        assertThat(roleArg.getValue(), is("role:can-do-this"));        
	}
	
    @Test
    public void updateBrokeredUserTest() throws IOException {
    	initMocks();

        IdentityProviderMapperModel mapperModel = getMapperModel("can-do-this"); 

        ClaimToRoleMapper mapper  = new ClaimToRoleMapper();
		
        mapper.create(mockSession);
        
        // 3. update user 1 with role: assert user now has role
    	BrokeredIdentityContext context = makeMockContext("can-do-this");
        mapper.updateBrokeredUser(mockSession, mockRealm, mockUser1, mapperModel, context);
        
        verify(mockUser1, times(1)).grantRole(grantedArg.capture());
        verify(mockUser1, never()).deleteRoleMapping(any(RoleModel.class));
        verify(mockRealm, atLeastOnce()).getRole(roleArg.capture());
        
        assertThat(grantedArg.getValue().getName(), is("role:can-do-this"));
        assertThat(roleArg.getValue(), is("role:can-do-this"));
        
        // 4. update without role: assert user no more has role
        context = makeMockContext("can-do-that");
        mapper.updateBrokeredUser(mockSession, mockRealm, mockUser2, mapperModel, context);
        
        verify(mockUser2, never()).grantRole(any(RoleModel.class));
        verify(mockUser2, times(1)).deleteRoleMapping(removedArg.capture());
        verify(mockRealm, atLeastOnce()).getRole(roleArg.capture());
        
        assertThat(removedArg.getValue().getName(), is("role:can-do-this"));
        assertThat(roleArg.getValue(), is("role:can-do-this"));
	}
}
