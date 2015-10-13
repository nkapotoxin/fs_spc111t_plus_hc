from keystone.common import sql
from keystone import exception
from keystone import identity
from keystone.identity.backends import sql as identity_sql
from keystone import config
from keystone.openstack.common import log as logging
from keystone.common import dependency
import datetime

LOG = logging.getLogger(__name__)

CONF = config.CONF

forbidden_delay = int(CONF.token.forbidden_delay)
forbidden_times = int(CONF.token.forbidden_times)
@dependency.requires('identity_api')
class Identity(identity_sql.Identity):
    # Identity interface
    def authenticate(self, user_id, password):
        session = sql.get_session()
        try:
            user_ref = self._get_user(session, user_id)
        except exception.UserNotFound:
            raise AssertionError('Invalid user / password')
        my_user_ref = identity.filter_user(user_ref.to_dict())
        wrong_times = my_user_ref['wrong_times'] or '0'
        wrong_times = int(wrong_times)
        if my_user_ref['last_error_time']:
            last_error_time_str = my_user_ref['last_error_time']
            lets = last_error_time_str
            # I admit that the code is very ugly....
            # I save the datetime string into database without any
            # transformations, so i have to transform string into a
            # datatime object, so that i can compare with utcnow, and
            # operate with timedelta.
            if len(lets)>19:
                ms = int(lets[20:])
            else:
                ms = 0
            last_error_time = datetime.datetime(year = int(lets[0:4]),
                                       month = int(lets[5:7]),
                                       day = int(lets[8:10]),
                                       hour = int(lets[11:13]),
                                       minute = int(lets[14:16]),
                                       second = int(lets[17:19]),
                                       microsecond = ms)
            now = datetime.datetime.utcnow()
            if forbidden_times > 0 and wrong_times != 0 and wrong_times >= forbidden_times :
                for_time = datetime.timedelta(seconds=forbidden_delay)
                time_to_go = (last_error_time + for_time)
                if now < time_to_go:
                    raise exception.TooManyErrors
                else:
                    my_user_ref['wrong_times'] = '0'
                    my_user_ref['last_error_time'] = None
                    self.identity_api.update_user(user_id, my_user_ref)
        if not self._check_password(password, user_ref):
            wrong_times_str = my_user_ref['wrong_times'] or '0'
            wrong_times = int(wrong_times_str)
            wrong_times = wrong_times + 1
            now = datetime.datetime.utcnow()
            my_user_ref['wrong_times'] = str(wrong_times)
            my_user_ref['last_error_time'] = str(now)
            self.identity_api.update_user(user_id,my_user_ref)
            raise AssertionError('Invalid user / password')

        if my_user_ref['wrong_times'] != '0' or my_user_ref['last_error_time'] is not None:
            my_user_ref['wrong_times'] = '0'
            my_user_ref['last_error_time'] = None
            self.identity_api.update_user(user_id, my_user_ref)
        return identity.filter_user(user_ref.to_dict())