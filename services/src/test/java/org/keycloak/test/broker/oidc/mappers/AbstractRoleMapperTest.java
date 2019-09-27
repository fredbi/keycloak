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

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.broker.provider.BrokeredIdentityContext;

import static org.mockito.Mockito.*;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.mockito.Captor;
import org.mockito.ArgumentCaptor;

import org.junit.Before;

/**
 *
 * @author Frederic BIDON
 */
public class AbstractRoleMapperTest {
	
	@Mock
    protected KeycloakSession mockSession;

	@Mock
	protected RealmModel mockRealm;
    
    @Mock
    protected IdentityProviderMapperModel mockMapper;
    
    @Mock
    protected UserModel mockUser1;
    
    @Mock
    protected UserModel mockUser2;
    
    @Mock
    protected BrokeredIdentityContext mockContext;

    @Mock
    protected RoleModel mockRole;
	
    @Captor
    protected ArgumentCaptor<String> roleArg;
    
    @Captor
    protected ArgumentCaptor<RoleModel> grantedArg;
    
    @Captor
    protected ArgumentCaptor<RoleModel> removedArg;
    
    @Before
    public void setup() throws Exception {
        MockitoAnnotations.initMocks(this);
    }
    
    protected void initMocks() {
    	
    	// test users
        when(mockUser1.getUsername()).thenReturn("user1");
        when(mockUser2.getUsername()).thenReturn("user2");
        
        doAnswer(new Answer<Void>() {
        	@Override
            public Void answer(InvocationOnMock invocation) throws Throwable {
        		return null;
        	}
        }).when(mockUser1).grantRole(any(RoleModel.class));
        
        doAnswer(new Answer<Void>() {
        	@Override
            public Void answer(InvocationOnMock invocation) throws Throwable {
        		return null;	
        	}
        }).when(mockUser2).grantRole(any(RoleModel.class));
        
        doAnswer(new Answer<Void>() {
        	@Override
            public Void answer(InvocationOnMock invocation) throws Throwable {
        		return null;
        	}
        }).when(mockUser1).deleteRoleMapping(any(RoleModel.class));
        
        doAnswer(new Answer<Void>() {
        	@Override
            public Void answer(InvocationOnMock invocation) throws Throwable {
        		return null;
        	}
        }).when(mockUser2).grantRole(any(RoleModel.class));
        
        when(mockRole.getName()).thenReturn("role:can-do-this");
        
        // role in realm
        when(mockRealm.getRole(anyString())).thenAnswer(new Answer<RoleModel>() {
            @Override
            public RoleModel answer(InvocationOnMock invocation) throws Throwable {
                Object[] arguments = invocation.getArguments();
                if (arguments != null && arguments.length > 0 && arguments[0] != null){
                    String roleName = (String) arguments[0];
                    if (roleName.contentEquals("role:can-do-this")) {
                    	return mockRole;
                    }
                }
                return null;
            }
        });
        
        // mock realm roles only
        when(mockRealm.getClientByClientId(anyString())).thenReturn((ClientModel)null);
    }
}