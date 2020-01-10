#!/usr/bin/env python
#
# File: models.py
# by @BitK_
#

# python2.
str = unicode


# can contain a value or None
def Maybe(constructor):
    return lambda data: constructor(data) if data else None


def Array(constructor):
    return lambda data: [constructor(entry) for entry in data]


class ApiData(object):
    def __init__(self, data):
        def load_class(cls):
            if not issubclass(cls, ApiData):
                return

            constructors = {
                k[2:]: v for k, v in cls.__dict__.items() if k.startswith("t_")
            }
            for key, constructor in constructors.items():
                setattr(self, key, constructor(data.get(key, None)))

            for base in cls.__bases__:
                load_class(base)

        load_class(self.__class__)


class Picture(ApiData):
    t_name = Maybe(str)
    t_original_name = Maybe(str)
    t_mime_type = Maybe(str)
    t_size = Maybe(int)
    t_url = Maybe(str)


class BusinessUnit(ApiData):
    t_name = str
    t_slug = str
    t_logo = Picture
    description = str


class Program(ApiData):
    t_managed = bool
    t_reports_count = int
    t_title = str
    t_slug = str
    t_public = bool
    t_hall_of_fame = bool
    t_bounty = bool
    t_gift = bool
    t_bounty_reward_min = Maybe(int)
    t_bounty_reward_low = Maybe(int)
    t_bounty_reward_medium = Maybe(int)
    t_bounty_reward_high = Maybe(int)
    t_bounty_reward_critical = Maybe(int)
    t_business_unit = BusinessUnit


class Scope(ApiData):
    t_scope = str
    t_scope_type = str


class Stats(ApiData):
    t_average_reward = Maybe(int)
    t_max_reward = Maybe(int)
    t_average_first_time_response = int
    t_total_reports = int
    t_total_reports_last24_hours = int
    t_total_reports_last7_days = int
    t_total_reports_current_month = int
    t_total_hunter_thanked = int


class ProgramDetails(Program):
    t_status = str
    t_rules_html = str
    t_scopes = Array(Scope)
    t_out_of_scope = Array(str)
    t_stats = Stats
    t_qualifying_vulnerability = Array(str)
    t_non_qualifying_vulnerability = Array(str)
    t_vpn_active = bool
    t_user_agent = Maybe(str)


class Error(ApiData):
    t_code = int
    t_message = str


class AuthToken(ApiData):
    t_token = str
    t_ttl = int


class Hunter(ApiData):
    # t_total_bu = int
    # t_has_wallet = bool
    # t_information_completed = bool
    t_username = str
    # t_slug = str
    # t_email = str
    # t_first_name = str
    # t_last_name = str
    # t_birthdate = str
    # t_nationality = str
    # t_country_of_residence = str
    # t_hunter_profile = HunterProfile
    # t_kyc_status = str
    # t_avatar = Picture
    # t_totp_enabled = bool
    # t_is_partner = bool
    # t_max_bu_number = int
    # t_mailing_accepted = bool
    # t_rights = Array(str)


class Pagination(ApiData):
    t_page = int
    t_nb_pages = int
    t_results_per_page = int


def Pages(apiobj):
    class Page(ApiData):
        t_items = Array(apiobj)
        t_pagination = Pagination

    return Page
