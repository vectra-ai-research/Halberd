import boto3
from botocore.exceptions import ClientError
from typing import Dict, List, Optional

class SessionManager:
    _sessions: Dict[str, Dict[str, boto3.Session]] = {}  # Class variable to store sessions

    @classmethod
    def create_session(cls, session_name, **kwargs) -> Dict[str, str]:
        """
        Create a new boto3 session with the given name and parameters.

        :param session_name: A unique identifier for this session
        :param kwargs: Arguments to pass to boto3.Session()
        :return: A dictionary with the session name and a status message
        """
        try:
            new_session = boto3.Session(**kwargs)
            # Verify the session is valid by calling STS
            sts = new_session.client('sts')
            sts.get_caller_identity()
            # Add session to session manager
            cls._sessions[session_name] = {"session":new_session,"active_session":False}
            
            return {"name" : session_name, "message" : "New session created"}
        except ClientError as e:
            return {"name" : session_name, "message" : "Failed to create session", "error" : str(e)}

    @classmethod
    def list_sessions(cls) -> List[Dict[str, str]]:
        """
        List all established sessions.
        
        :return: List of all AWS sessions available currently
        """
        if not cls._sessions:
            return []
        else:
            sessions_list = []
            for name, session_details in cls._sessions.items():
                session = session_details.get("session")
                sessions_list.append(
                    {
                        "session_name" : name,
                        "region" : session.region_name,
                        "profile" : session.profile_name
                    }
                )
            return sessions_list

    @classmethod            
    def get_session(cls, session_name) -> Optional[boto3.Session]:
        """
        Retrieve a session by its name.
        
        :param session_name: The name of the session to retrieve
        :return: The requested boto3.Session object, or None if not found
        """
        session_data = cls._sessions.get(session_name, None)
        return session_data['session'] if session_data else None
    
    @classmethod            
    def get_active_session(cls) -> Optional[boto3.Session]:
        """
        Retrieve active session.
        
        :return: The active boto3.Session object, or None if not found
        """
        for session_name, session_data in cls._sessions.items():
            if session_data['active_session'] == True:
                return cls.get_session(session_name)
        
        return None
    
    @classmethod            
    def get_session_details_as_json(cls, session_name = None)-> Dict[str, str]:
        """
        Retrieve session details by its name in json format. If no session is specified, return info for active session.
        
        :param session_name: The name of the session to retrieve
        :return: session details, or an empty dict if not found
        """
        if session_name:
            session = cls.get_session(session_name)
        else:
            session = cls.get_active_session()
        
        if session:
            return {
                "access_key": session.get_credentials().access_key,
                "secret_key": session.get_credentials().secret_key,
                "token": session.get_credentials().token,
                "available_profiles": session.available_profiles
            }
        
        # Return {} if no session found
        return {}
    
    @classmethod
    def set_active_session(cls, session_name) -> None:
        """
        Set a session as default/active session.This session is used across Halberd AWS techniques.

        :param session_name: The name of the session to set as active
        :raises ValueError: If the session is not found
        """
        if session_name not in cls._sessions:
            raise ValueError("Session not found")
        
        # Set selected session as default session
        boto3.DEFAULT_SESSION = cls._sessions[session_name]["session"]
        # Update the _sessions object with latest defautl session
        cls._sessions[session_name]['active_session']= True
        
        
    def remove_session(cls, session_name) -> None:
        """
        Remove a session by its name.

        :param session_name: The name of the session to remove
        :raises ValueError: If the session is not found
        """
        if session_name not in cls._sessions:
            raise ValueError("Session not found")
        
        del cls._sessions[session_name]
        
    def get_user_details(cls) -> Optional[Dict[str, str]]:
        """
        Retrieves user detail from active session

        :return: A dictionary with user details, or None if no active session
        """
        active_session = cls.get_active_session()

        if active_session:
            sts = active_session.client('sts')
            caller_info = sts.get_caller_identity()

            caller_info_output = {
                'user_id' : caller_info.get('UserId', 'N/A'),
                'account' : caller_info.get('Account', 'N/A'),
                'user_arn' : caller_info.get('Arn', 'N/A')
            }
            return caller_info_output
        else:
            return None