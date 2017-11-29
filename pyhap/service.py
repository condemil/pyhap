from abc import abstractmethod
from typing import (
    List,
    Type,
)
from uuid import UUID

from pyhap.characteristic import Characteristic
from pyhap.util import (
    aduuid_to_uuid,
    uuid_to_aduuid,
)


class Service:
    def __init__(self):
        self.instance_id = None  # set by bridge
        self.characteristics: List[Characteristic] = []

    @property
    @abstractmethod
    def service_uuid(self) -> UUID:
        raise NotImplementedError()

    def add_characteristic(self, characteristic: Characteristic):
        self.characteristics.append(characteristic)

    def __json__(self):
        return {
            'type': uuid_to_aduuid(self.service_uuid),
            'iid': self.instance_id,
            'characteristics': self.characteristics
        }


def generate_service(name, service_uuid: str) -> Type[Service]:
    return type(name, (Service,), {
        'service_uuid': property(lambda self: aduuid_to_uuid(service_uuid))
    })


AccessoryInformationService = generate_service('AccessoryInformationService', '3e')
FanService = generate_service('Fan', '40')
GarageDoorOpenerService = generate_service('GarageDoorOpener', '41')
LightbulbService = generate_service('LightbulbService', '43')
LockManagementService = generate_service('LockManagementService', '44')
LockMechanismService = generate_service('LockMechanismService', '45')
OutletService = generate_service('OutletService', '47')
SwitchService = generate_service('SwitchService', '49')
ThermostatService = generate_service('ThermostatService', '4a')
AirQualityService = generate_service('AirQualityService', '8d')
SecuritySystemService = generate_service('SecuritySystemService', '7e')
CarbonMonoxideSensorService = generate_service('CarbonMonoxideSensorService', '7f')
ContactSensorService = generate_service('ContactSensorService', '80')
HumiditySensorService = generate_service('HumiditySensorService', '82')
LeakSensorService = generate_service('LeakSensorService', '83')
LightSensorService = generate_service('LightSensorService', '84')
MotionSensorService = generate_service('MotionSensorService', '85')
OccupancySensorService = generate_service('MotionSensorService', '86')
SmokeSensorService = generate_service('SmokeSensorService', '87')
StatelessProgrammableSwitchService = generate_service('StatelessProgrammableSwitchService', '89')
TemperatureService = generate_service('TemperatureService', '8A')
WindowService = generate_service('WindowService', '8B')
WindowCoveringService = generate_service('WindowCoveringService', '8C')
BatteryService = generate_service('BatteryService', '96')
CarbonDioxideSensorService = generate_service('CarbonDioxideSensorService', '97')
CameraRTPStreamManagementService = generate_service('CameraRTPStreamManagementService', '110')
MicrophoneService = generate_service('MicrophoneService', '112')
SpeakerService = generate_service('SpeakerService', '113')
DoorbellService = generate_service('DoorbellService', '121')
FanV2Service = generate_service('FanV2Service', 'B7')
SlatService = generate_service('SlatService', 'B9')
FilterMaintenanceService = generate_service('FilterMaintenanceService', 'BA')
AirPurifierService = generate_service('AirPurifierService', 'BB')
ServiceLabelService = generate_service('ServiceLabelService', 'CC')
