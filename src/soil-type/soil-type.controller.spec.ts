import { Test, TestingModule } from '@nestjs/testing';
import { SoilTypeController } from './soil-type.controller';

describe('SoilTypeController', () => {
  let controller: SoilTypeController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [SoilTypeController],
    }).compile();

    controller = module.get<SoilTypeController>(SoilTypeController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
